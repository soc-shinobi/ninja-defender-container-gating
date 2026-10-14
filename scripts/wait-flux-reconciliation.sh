#!/usr/bin/env bash
# Wait for Azure's Flux status to observe this workflow's pushed commit and report
# the selected namespace Kustomization as Ready or NotReady.
#
# DISCLAIMER - a demo convenience, not a deployment gate. In GitOps the pipeline's job
# ends at `git push`; Flux owns the rollout and reports back itself (GitHub commit status
# via app/k8s/40-flux-notifications.yaml). This step only reads Flux conditions through
# Azure Resource Manager, so it needs no cluster credentials, but it also cannot see
# which image a pod actually runs:
#   Ready     = Flux applied a revision that contains this commit and its health checks
#               passed. It does not prove the pod runs exactly the pushed image.
#   NotReady  = Flux attempted that revision and the failure message is an admission
#               denial (EXPECTED_DENIAL_PATTERN). Any other failure - a missing service
#               account, a bad manifest - is reported as unexpected, not as "blocked".
set -euo pipefail

: "${AZURE_RESOURCE_GROUP:?set AZURE_RESOURCE_GROUP}"
: "${AKS_NAME:?set AKS_NAME}"
: "${GITOPS_COMMIT:?set GITOPS_COMMIT to the pushed commit SHA}"
: "${FLUX_KUSTOMIZATION:?set FLUX_KUSTOMIZATION to blocked or allowed}"
: "${EXPECTED_FLUX_STATE:?set EXPECTED_FLUX_STATE to Ready or NotReady}"

if [[ "$FLUX_KUSTOMIZATION" != blocked && "$FLUX_KUSTOMIZATION" != allowed ]]; then
  echo "FLUX_KUSTOMIZATION must be blocked or allowed" >&2
  exit 2
fi
if [[ "$EXPECTED_FLUX_STATE" != Ready && "$EXPECTED_FLUX_STATE" != NotReady ]]; then
  echo "EXPECTED_FLUX_STATE must be Ready or NotReady" >&2
  exit 2
fi

FLUX_CONFIGURATION="${FLUX_CONFIGURATION:-demo-apps}"
TIMEOUT_SECONDS="${FLUX_WAIT_TIMEOUT_SECONDS:-600}"
POLL_SECONDS="${FLUX_WAIT_POLL_SECONDS:-10}"
SOURCE_ERROR_GRACE_SECONDS="${FLUX_SOURCE_ERROR_GRACE_SECONDS:-120}"
# What a gate denial looks like in the Kustomization's Ready message, e.g.
#   admission webhook "defender-admission-controller.mdc.svc" denied the request: ...
EXPECTED_DENIAL_PATTERN="${EXPECTED_DENIAL_PATTERN:-denied the request}"
STATUS_NAME="${FLUX_CONFIGURATION}-${FLUX_KUSTOMIZATION}"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP}/providers/Microsoft.ContainerService/managedClusters/${AKS_NAME}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/${FLUX_CONFIGURATION}"
URL="https://management.azure.com${RESOURCE_ID}?api-version=2023-05-01"
STARTED_AT="${SECONDS}"
LAST_SYNCED_COMMIT=""
LAST_READY=""
LAST_REASON=""
LAST_MESSAGE=""
LAST_SOURCE_MESSAGE=""
LAST_FLUX_STATE="Unknown"
LAST_APPLIED_REVISION=""

DISCLAIMER="Demo check, not a deployment gate: it reads Flux conditions through Azure Resource Manager and cannot see which image a pod runs. Flux's own GitHub commit status (app/k8s/40-flux-notifications.yaml) is the GitOps-native signal."

# True when revision $1 (a Flux "main@sha1:<sha>" or bare sha) is GITOPS_COMMIT or a later
# commit that contains it - someone may push on top while Flux is still catching up.
contains_commit() {
  local sha="${1##*:}"
  [[ -n "$sha" ]] || return 1
  [[ "$sha" == "$GITOPS_COMMIT" ]] && return 0
  git rev-parse --git-dir >/dev/null 2>&1 || return 1
  if ! git cat-file -e "${sha}^{commit}" 2>/dev/null; then
    git fetch --quiet --depth=200 origin main 2>/dev/null || true
  fi
  git merge-base --is-ancestor "$GITOPS_COMMIT" "$sha" 2>/dev/null
}

if ! AKS_POWER_STATE="$(az aks show --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AKS_NAME" --query 'powerState.code' -o tsv --only-show-errors 2>&1)"; then
  echo "::error::Unable to read AKS power state for ${AZURE_RESOURCE_GROUP}/${AKS_NAME}: ${AKS_POWER_STATE}"
  exit 1
fi
if [[ "$AKS_POWER_STATE" != Running ]]; then
  echo "::error::AKS ${AZURE_RESOURCE_GROUP}/${AKS_NAME} is ${AKS_POWER_STATE:-unknown}, not Running; Flux cannot reconcile workloads"
  exit 1
fi
echo "AKS ${AZURE_RESOURCE_GROUP}/${AKS_NAME} power state: Running."

# ---- log colours -------------------------------------------------------------------------
# GitHub renders ANSI in the step log (not in ::notice/::error annotations, which stay plain).
C_RESET=$'\033[0m'; C_DIM=$'\033[90m'
C_GREEN=$'\033[1;32m'; C_RED=$'\033[1;31m'; C_YELLOW=$'\033[1;33m'; C_CYAN=$'\033[36m'
C_MAGENTA=$'\033[35m'

# Colour a Flux Ready value: True green, False red, anything else (pending, Unknown) yellow.
ready_colour() {
  case "$1" in
    True) printf '%s%s%s' "$C_GREEN" "$1" "$C_RESET" ;;
    False) printf '%s%s%s' "$C_RED" "$1" "$C_RESET" ;;
    *) printf '%s%s%s' "$C_YELLOW" "${1:-pending}" "$C_RESET" ;;
  esac
}

# Split an admission denial into its parts. Flux reports it as
#   Deployment/<ns>/<name> dry-run failed: admission webhook "<hook>" denied the request:
#   [<image>:]<reason>[\nVerifier rule name: <rule>]
# Sets DENY_OBJECT, DENY_WEBHOOK, DENY_IMAGE, DENY_REASON, DENY_RULE (empty when absent).
parse_denial() {
  local msg="$1" rest
  DENY_OBJECT=""; DENY_WEBHOOK=""; DENY_IMAGE=""; DENY_REASON=""; DENY_RULE=""
  [[ "$msg" =~ ^([^[:space:]]+)\ dry-run\ failed ]] && DENY_OBJECT="${BASH_REMATCH[1]}"
  [[ "$msg" =~ admission\ webhook\ \"([^\"]+)\" ]] && DENY_WEBHOOK="${BASH_REMATCH[1]}"
  [[ "$msg" =~ Verifier\ rule\ name:\ *([^[:space:]]+) ]] && DENY_RULE="${BASH_REMATCH[1]}"
  rest="${msg#*denied the request: }"
  [[ "$rest" == "$msg" ]] && rest=""
  rest="${rest%%Verifier rule name:*}"
  rest="$(tr '\n' ' ' <<< "$rest" | sed -E 's/[[:space:]]+$//')"
  # registry/repo[:tag][@sha256:...]:<reason> - the image is everything up to the last ':'
  # that is followed by a space-containing reason.
  if [[ "$rest" =~ ^([a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]+)?):([A-Z].*)$ ]]; then
    DENY_IMAGE="${BASH_REMATCH[1]}"; DENY_REASON="${BASH_REMATCH[4]}"
  else
    DENY_REASON="$rest"
  fi
}

# Framed result banner: banner <colour> <icon> <title>
banner() {
  local colour="$1" icon="$2" title="$3" line
  line="$(printf '%*s' 66 '' | tr ' ' '-')"
  printf '\n%s+%s+%s\n' "$colour" "$line" "$C_RESET"
  printf '%s|  %s  %-61s|%s\n' "$colour" "$icon" "$title" "$C_RESET"
  printf '%s+%s+%s\n' "$colour" "$line" "$C_RESET"
}

# Log the Flux message: an admission denial field by field, anything else as one dim line.
print_detail() {
  local msg="$1"
  [[ -n "$msg" ]] || return 0
  if grep -qiE "$EXPECTED_DENIAL_PATTERN" <<< "$msg"; then
    parse_denial "$msg"
    [[ -n "$DENY_OBJECT" ]]  && printf '  %sobject %s  %s\n' "$C_DIM" "$C_RESET" "$DENY_OBJECT"
    [[ -n "$DENY_WEBHOOK" ]] && printf '  %swebhook%s  %s%s%s\n' "$C_DIM" "$C_RESET" "$C_CYAN" "$DENY_WEBHOOK" "$C_RESET"
    [[ -n "$DENY_IMAGE" ]]   && printf '  %simage  %s  %s%s%s\n' "$C_DIM" "$C_RESET" "$C_MAGENTA" "$DENY_IMAGE" "$C_RESET"
    [[ -n "$DENY_REASON" ]]  && printf '  %sreason %s  %s%s%s\n' "$C_DIM" "$C_RESET" "$C_RED" "$DENY_REASON" "$C_RESET"
    [[ -n "$DENY_RULE" ]]    && printf '  %srule   %s  %s%s%s\n' "$C_DIM" "$C_RESET" "$C_YELLOW" "$DENY_RULE" "$C_RESET"
  else
    printf '  %sFlux detail:%s %s\n' "$C_DIM" "$C_RESET" "$msg"
  fi
  echo ""
}

write_summary() {
  local result="$1" icon="${2:-🔄}"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "> [!WARNING]"
      echo "> **Notice:** ${DISCLAIMER}"
      echo ""
      echo "### ${icon} Flux reconciliation: ${result}"
      echo "- Configuration: \`${FLUX_CONFIGURATION}\`"
      echo "- Kustomization: \`${STATUS_NAME}\`"
      echo "- Workflow commit: \`${GITOPS_COMMIT}\`"
      echo "- Flux source commit: \`${LAST_SYNCED_COMMIT:-not observed}\`"
      echo "- Kustomization revision: \`${LAST_APPLIED_REVISION:-not observed}\`"
      echo "- Overall Flux compliance: \`${LAST_FLUX_STATE}\`"
      echo "- Ready condition: \`${LAST_READY:-not observed}\`"
      echo "- Reason: \`${LAST_REASON:-none}\`"
      if [[ -n "$LAST_MESSAGE" ]] && grep -qiE "$EXPECTED_DENIAL_PATTERN" <<< "$LAST_MESSAGE"; then
        parse_denial "$LAST_MESSAGE"
        echo ""
        echo "| Admission denial | |"
        echo "|---|---|"
        [[ -n "$DENY_OBJECT" ]]  && echo "| Object | \`${DENY_OBJECT}\` |"
        [[ -n "$DENY_WEBHOOK" ]] && echo "| Webhook | \`${DENY_WEBHOOK}\` |"
        [[ -n "$DENY_IMAGE" ]]   && echo "| Image | \`${DENY_IMAGE}\` |"
        [[ -n "$DENY_REASON" ]]  && echo "| Reason | 🚫 ${DENY_REASON//|/\\|} |"
        [[ -n "$DENY_RULE" ]]    && echo "| Defender rule | \`${DENY_RULE}\` |"
        echo ""
        echo "<details><summary>Full Flux message</summary>"
        echo ""
        echo '```'
        echo "${LAST_MESSAGE}"
        echo '```'
        echo "</details>"
      elif [[ -n "$LAST_MESSAGE" ]]; then
        echo "- Flux message: ${LAST_MESSAGE}"
      elif [[ -n "$LAST_SOURCE_MESSAGE" ]]; then
        echo "- Source message: ${LAST_SOURCE_MESSAGE}"
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  fi
}

echo "Waiting for Flux configuration ${FLUX_CONFIGURATION} to observe commit ${GITOPS_COMMIT}."
echo "Checking Kustomization ${STATUS_NAME}; expected state: ${EXPECTED_FLUX_STATE}."
# Yellow on purpose: a run page annotation plus a log banner, so nobody reads a green
# step as "the pushed image is running".
echo "::warning title=Notice - demo check, not a deployment gate::${DISCLAIMER}"
printf '\n\033[1;33m╔══════════════════════════════════════════════════════════════════╗\n'
printf '║  ⚠  NOTICE: demo check, not a deployment gate                    ║\n'
printf '╚══════════════════════════════════════════════════════════════════╝\033[0m\n'
printf '\033[33m%s\033[0m\n\n' "$DISCLAIMER" | fold -s -w 100

while (( SECONDS - STARTED_AT < TIMEOUT_SECONDS )); do
  if ! RESOURCE="$(az rest --method get --url "$URL" -o json 2>&1)"; then
    LAST_MESSAGE="$RESOURCE"
    echo "::error::Unable to read Flux status through Azure Resource Manager: $RESOURCE"
    write_summary "status query failed" "❌"
    exit 1
  fi

  LAST_SYNCED_COMMIT="$(jq -r '.properties.sourceSyncedCommitId // ""' <<< "$RESOURCE")"
  LAST_FLUX_STATE="$(jq -r '.properties.complianceState // "Unknown"' <<< "$RESOURCE")"
  SOURCE_CONDITION="$(jq -c '[.properties.statuses[]? | select(.kind == "GitRepository") | .statusConditions[]? | select(.type == "Ready")][-1] // {}' <<< "$RESOURCE")"
  SOURCE_READY="$(jq -r '.status // ""' <<< "$SOURCE_CONDITION")"
  LAST_SOURCE_MESSAGE="$(jq -r '.message // ""' <<< "$SOURCE_CONDITION")"

  KUSTOMIZATION="$(jq -c --arg name "$STATUS_NAME" '[.properties.statuses[]? | select(.kind == "Kustomization" and .name == $name)][0] // {}' <<< "$RESOURCE")"
  READY_CONDITION="$(jq -c '[.statusConditions[]? | select(.type == "Ready")][-1] // {}' <<< "$KUSTOMIZATION")"
  LAST_READY="$(jq -r '.status // ""' <<< "$READY_CONDITION")"
  LAST_REASON="$(jq -r '.reason // ""' <<< "$READY_CONDITION")"
  LAST_MESSAGE="$(jq -r '.message // ""' <<< "$READY_CONDITION")"
  # The revision the KUSTOMIZATION worked on, not just what the source fetched: Ready says
  # "Applied revision: main@sha1:<sha>", a failing attempt names it in the Reconciling
  # condition ("... for revision main@sha1:<sha> ..."). Until it moves, Ready=True still
  # describes the previous commit.
  if [[ "$LAST_READY" == True ]]; then
    LAST_APPLIED_REVISION="$(grep -oE '[[:alnum:]_./-]+@sha1:[0-9a-f]{40}' <<< "$LAST_MESSAGE" | head -1 || true)"
  else
    LAST_APPLIED_REVISION="$(jq -r '[.statusConditions[]?.message // ""] | join("\n")' <<< "$KUSTOMIZATION" \
      | grep -oE '[[:alnum:]_./-]+@sha1:[0-9a-f]{40}' | head -1 || true)"
  fi

  printf '%s%s%s  %sFlux%s %s  %ssource%s %s  %srevision%s %s  %sReady%s %s %s%s%s\n' \
    "$C_DIM" "$(date -u +%H:%M:%S)" "$C_RESET" \
    "$C_DIM" "$C_RESET" "$LAST_FLUX_STATE" \
    "$C_DIM" "$C_RESET" "$(c="${LAST_SYNCED_COMMIT:0:7}"; echo "${c:-pending}")" \
    "$C_DIM" "$C_RESET" "$(sed -E 's/@sha1:([0-9a-f]{7})[0-9a-f]*/@\1/' <<< "${LAST_APPLIED_REVISION:-pending}")" \
    "$C_DIM" "$C_RESET" "$(ready_colour "$LAST_READY")" "$C_DIM" "${LAST_REASON}" "$C_RESET"

  if contains_commit "$LAST_APPLIED_REVISION"; then
    if [[ "$EXPECTED_FLUX_STATE" == Ready && "$LAST_READY" == True ]]; then
      echo "::notice::Flux reconciled ${STATUS_NAME} successfully at ${LAST_SYNCED_COMMIT}."
      banner "$C_GREEN" "✔" "${STATUS_NAME} Ready - as expected (admitted)"
      print_detail "$LAST_MESSAGE"
      write_summary "Ready" "✅"
      exit 0
    fi
    if [[ "$EXPECTED_FLUX_STATE" == NotReady && "$LAST_READY" == False ]]; then
      if ! grep -qiE "$EXPECTED_DENIAL_PATTERN" <<< "$LAST_MESSAGE"; then
        echo "::error::${STATUS_NAME} is NotReady, but not because admission denied it (${LAST_REASON}: ${LAST_MESSAGE})"
        banner "$C_RED" "✘" "${STATUS_NAME} NotReady - but NOT an admission denial"
        print_detail "$LAST_MESSAGE"
        write_summary "NotReady for an unexpected reason" "❌"
        exit 1
      fi
      echo "::notice::Flux has reconciled ${STATUS_NAME} and reports NotReady as expected for the blocked namespace."
      banner "$C_GREEN" "✔" "${STATUS_NAME} NotReady - as expected (admission denied)"
      print_detail "$LAST_MESSAGE"
      write_summary "NotReady (expected blocked outcome)" "🚫"
      exit 0
    fi
    if [[ "$LAST_READY" == True || "$LAST_READY" == False ]]; then
      echo "::error::Flux reached an unexpected state for ${STATUS_NAME}: Ready=${LAST_READY}; ${LAST_REASON}: ${LAST_MESSAGE}"
      banner "$C_RED" "✘" "${STATUS_NAME} Ready=${LAST_READY} - expected ${EXPECTED_FLUX_STATE}"
      print_detail "$LAST_MESSAGE"
      write_summary "unexpected ${LAST_READY} state" "❌"
      exit 1
    fi
  elif ! contains_commit "$LAST_SYNCED_COMMIT" \
       && [[ "$SOURCE_READY" == False && $((SECONDS - STARTED_AT)) -ge "$SOURCE_ERROR_GRACE_SECONDS" ]]; then
    echo "::error::Flux cannot fetch the repository, so it has not observed ${GITOPS_COMMIT}: ${LAST_SOURCE_MESSAGE}"
    LAST_MESSAGE=""
    banner "$C_RED" "✘" "Flux cannot fetch the repository"
    write_summary "source error" "❌"
    exit 1
  fi

  sleep "$POLL_SECONDS"
done

echo "::error::Timed out after ${TIMEOUT_SECONDS}s waiting for Flux to process ${GITOPS_COMMIT}; source=${LAST_SYNCED_COMMIT:-pending}, ${STATUS_NAME} Ready=${LAST_READY:-pending}, reason=${LAST_REASON:-unknown}, message=${LAST_MESSAGE:-$LAST_SOURCE_MESSAGE}"
banner "$C_RED" "⏱" "timed out after ${TIMEOUT_SECONDS}s waiting for ${STATUS_NAME}"
write_summary "timed out" "⏱️"
exit 1
