#!/usr/bin/env bash
# Update only the Git authentication on the existing Azure Flux configuration.
# The PAT is supplied by GitHub Actions and never written to disk or printed.
set -euo pipefail

: "${AZURE_RESOURCE_GROUP:?set AZURE_RESOURCE_GROUP}"
: "${AKS_NAME:?set AKS_NAME}"
: "${ACR_LOGIN_SERVER:?set ACR_LOGIN_SERVER}"
: "${FLUX_GITHUB_TOKEN:?set the GitHub Actions secret FLUX_GITHUB_TOKEN}"
# Flux syncs the repo this runs from: the Actions repository, else the local git origin.
if [[ -z "${GIT_REPO_URL:-}" ]]; then
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    GIT_REPO_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}"
  else
    GIT_REPO_URL="$(git remote get-url origin 2>/dev/null | sed -E 's#^git@github\.com:#https://github.com/#; s#\.git$##')"
  fi
fi
: "${GIT_REPO_URL:?set GIT_REPO_URL or run from a git checkout with an origin remote}"
export GIT_REPO_URL

# The webapp's heartbeat target: the control panel's public /healthz (isolation drill). Flux
# substitutes it into the panel-heartbeat ConfigMap; the hostname changes with each fresh
# deployment, so it is read here instead of living in git.
if [[ -z "${HEARTBEAT_URL:-}" ]]; then
  FQDN="$(az containerapp list -g "$AZURE_RESOURCE_GROUP" --query "[0].properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)"
  [[ -n "$FQDN" ]] && HEARTBEAT_URL="https://$FQDN/healthz"
fi
export HEARTBEAT_URL="${HEARTBEAT_URL:-}"

FLUX_CONFIGURATION="${FLUX_CONFIGURATION:-demo-apps}"
TIMEOUT_SECONDS="${FLUX_SOURCE_WAIT_TIMEOUT_SECONDS:-600}"
POLL_SECONDS="${FLUX_SOURCE_WAIT_POLL_SECONDS:-15}"
SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
RESOURCE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${AZURE_RESOURCE_GROUP}/providers/Microsoft.ContainerService/managedClusters/${AKS_NAME}/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/${FLUX_CONFIGURATION}"
URL="https://management.azure.com${RESOURCE_ID}?api-version=2023-05-01"

echo ">> Updating Flux configuration ${FLUX_CONFIGURATION} (repo ${GIT_REPO_URL})"
DEPLOYMENT_NAME="flux-config-${GITHUB_RUN_ID:-$(date +%Y%m%d%H%M%S)}"
az deployment group create \
  --name "$DEPLOYMENT_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --template-file infra/modules/flux.bicep \
  --parameters infra/flux.bicepparam \
  --only-show-errors \
  --query properties.provisioningState \
  --output tsv

echo ">> Waiting for Flux to authenticate and sync the repository"
STARTED_AT="${SECONDS}"
LAST_MESSAGE=""
while (( SECONDS - STARTED_AT < TIMEOUT_SECONDS )); do
  if ! RESOURCE="$(az rest --method get --url "$URL" -o json 2>&1)"; then
    echo "::error::Unable to read Flux status through Azure Resource Manager: $RESOURCE"
    exit 1
  fi

  SOURCE="$(jq -c '[.properties.statuses[]? | select(.kind == "GitRepository")][0] // {}' <<< "$RESOURCE")"
  READY="$(jq -r '[.statusConditions[]? | select(.type == "Ready")][-1].status // ""' <<< "$SOURCE")"
  REASON="$(jq -r '[.statusConditions[]? | select(.type == "Ready")][-1].reason // ""' <<< "$SOURCE")"
  LAST_MESSAGE="$(jq -r '[.statusConditions[]? | select(.type == "Ready")][-1].message // ""' <<< "$SOURCE")"
  COMMIT="$(jq -r '.properties.sourceSyncedCommitId // ""' <<< "$RESOURCE")"

  echo "Flux GitRepository Ready=${READY:-pending}${REASON:+ (${REASON})}; syncedCommit=${COMMIT:-pending}"
  if [[ "$READY" == True && -n "$COMMIT" ]]; then
    echo "::notice::Flux authenticated and synced ${GIT_REPO_URL} at ${COMMIT}."
    exit 0
  fi
  sleep "$POLL_SECONDS"
done

echo "::error::Flux did not authenticate and sync within ${TIMEOUT_SECONDS}s: ${LAST_MESSAGE:-no source status received}"
exit 1
