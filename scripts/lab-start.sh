#!/usr/bin/env bash
# On-demand lab startup (AKS + Container App) with readiness checks.
# The "bring it up before the demo" front door. lab-park.sh is the engine; this
# script starts everything, then WAITS until it is actually usable and prints
# the URL, so you know when you can start talking.
#
#   1. AKS start + Container App minReplicas 1   (via lab-park.sh start)
#   2. wait: AKS powerState Running
#   3. wait: all nodes Ready                      (if kubectl is available)
#   4. wait: Container App runningStatus Running, print its FQDN
#
# Usage: scripts/lab-start.sh            (or: make lab-start)
# Env:   RG, AKS, APP, NAME_PREFIX, PARK_ACA (same as lab-park.sh)
#        WAIT_TIMEOUT  seconds per wait phase (default 600)
set -euo pipefail

# needs the `containerapp` CLI extension; `make deploy` installs it (scripts/az-prereqs.sh).
# run standalone on a fresh machine, let az fetch it instead of prompting.
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-600}"

c() { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }
wait_for() {   # wait_for <label> <cmd that prints value> <expected> ; polls every 10s
  local label="$1" cmd="$2" want="$3" t=0 got=""
  while (( t < WAIT_TIMEOUT )); do
    got="$(eval "$cmd" 2>/dev/null || true)"
    if [[ "$got" == "$want" ]]; then c '1;32' "✔ $label: $got"; return 0; fi
    printf '  … %s: %s (%ss)\n' "$label" "${got:-<none>}" "$t"; sleep 10; t=$((t+10))
  done
  c '1;31' "✘ timeout waiting for $label (last: ${got:-<none>})"; return 1
}

c '1;36' "╔══════════════════════════════════════════╗"
c '1;36' "║  lab-start · AKS + Container App          ║"
c '1;36' "╚══════════════════════════════════════════╝"

# 1) start everything
bash "$HERE/lab-park.sh" start

# 2) AKS control plane running
wait_for "AKS powerState" "az aks show -g $RG -n $AKS --query powerState.code -o tsv" "Running"

# 3) nodes Ready (best effort: needs kubectl; skip cleanly if absent)
if command -v kubectl >/dev/null 2>&1; then
  az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing -o none 2>/dev/null || true
  wait_for "AKS nodes Ready" \
    "kubectl get nodes -o jsonpath='{range .items[*]}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}' | sort -u | tr -d '\\n'" \
    "True"
  kubectl get nodes 2>/dev/null || true
else
  c '1;33' "ℹ kubectl not found - skipping node readiness check"
fi

# 4) Container App running + URL
if [[ "${PARK_ACA:-true}" == "true" ]] && az containerapp show -g "$RG" -n "$APP" -o none 2>/dev/null; then
  wait_for "Container App status" "az containerapp show -g $RG -n $APP --query properties.runningStatus -o tsv" "Running"
  FQDN="$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv 2>/dev/null || true)"
  [[ -n "$FQDN" ]] && c '1;32' "✔ control panel: https://$FQDN"
fi

echo
c '1;32' "✔ lab is up."
c '1;33' "ℹ service IPs on AKS are NEW addresses after a start; Flux (if enabled) re-reconciles app/k8s and the gate beat will fire again."
