#!/usr/bin/env bash
# The isolation drill: give the x-mdc-allowed web app a target to heartbeat against.
#
# The app (app/aks-webapp/app.py, _heartbeat_loop) GETs HEARTBEAT_URL every 15s and logs
# "[heartbeat] OK" or "[heartbeat] ERROR" to stdout. Pointed at the control panel's public
# /healthz, it proves egress works - until the pod is isolated from Defender XDR, when the
# network policy cuts egress and the log turns red in the panel console.
#
# The URL is now GitOps: the panel-heartbeat ConfigMap lives in app/k8s/x-mdc-allowed and Flux
# fills in HEARTBEAT_URL (postBuild substitute) from the Container App's ingress FQDN, set when
# the Flux configuration is deployed (infra/modules/flux.bicep, deploy.sh, update-flux-auth).
# Writing the ConfigMap by hand would only be reverted on the next sync.
#
# This script is for after the panel got a NEW hostname (fresh ACA deployment): it re-runs the
# Flux configuration deployment, which reads the current FQDN. Same as running the
# "Update Flux Git credentials" workflow.
set -euo pipefail
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

RG="${RG:-rg-defdemo}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"

FQDN="$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)"
[[ -n "$FQDN" ]] || { echo "✘ could not read the ingress FQDN of $APP in $RG" >&2; exit 1; }
export HEARTBEAT_URL="https://$FQDN/healthz"
printf '\033[1;36m▶ HEARTBEAT_URL=%s -> Flux configuration\033[0m\n' "$HEARTBEAT_URL"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  # The workflow holds the Flux PAT and the OIDC login; it reads the same FQDN itself.
  gh workflow run update-flux-auth.yml --ref main
  echo ">> started the 'Update Flux Git credentials' workflow; Flux picks the URL up after it."
else
  : "${FLUX_GITHUB_TOKEN:?set FLUX_GITHUB_TOKEN (Flux PAT) or log in with gh}"
  AZURE_RESOURCE_GROUP="$RG" AKS_NAME="${AKS:-${NAME_PREFIX:-defdemo}-aks}" \
    ACR_LOGIN_SERVER="${ACR_LOGIN_SERVER:?set ACR_LOGIN_SERVER}" \
    bash "$(dirname "$0")/../../scripts/update-flux-auth.sh"
fi
echo ">> Watch it: control panel > command library > binary drift + isolation > 1. heartbeat log"
