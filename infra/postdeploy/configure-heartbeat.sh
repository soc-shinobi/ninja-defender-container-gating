#!/usr/bin/env bash
# The isolation drill: give the x-mdc-allowed web app a target to heartbeat against.
#
# The app (app/aks-webapp/app.py, _heartbeat_loop) GETs HEARTBEAT_URL every 15s and logs
# "[heartbeat] OK" or "[heartbeat] ERROR" to stdout. Pointed at the control panel's public
# /healthz, it proves egress works - until the pod is isolated from Defender XDR, when the
# network policy cuts egress and the log turns red in the panel console.
#
# The URL lives in a ConfigMap rather than in git because the Container App hostname changes
# with every fresh deployment. Flux does not own this ConfigMap (it is not in the repo), so a
# sync never prunes it; the Deployment reads it with optional: true.
set -euo pipefail
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"
NS="${HEARTBEAT_NAMESPACE:-x-mdc-allowed}"

FQDN="$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)"
if [[ -z "$FQDN" ]]; then
  echo "✘ could not read the ingress FQDN of $APP in $RG" >&2
  exit 1
fi
URL="https://$FQDN/healthz"

KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing \
  --file "$KUBECONFIG_FILE" -o none
K=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin")

printf '\033[1;36m▶ ConfigMap %s/panel-heartbeat  HEARTBEAT_URL=%s\033[0m\n' "$NS" "$URL"
"${K[@]}" -n "$NS" create configmap panel-heartbeat \
  --from-literal=HEARTBEAT_URL="$URL" --dry-run=client -o yaml | "${K[@]}" apply -f -

# envFrom is read at pod start, so restart to pick a changed URL up.
"${K[@]}" -n "$NS" rollout restart deploy/webapp
"${K[@]}" -n "$NS" rollout status deploy/webapp --timeout=180s \
  && printf '\033[1;32m✔ heartbeat configured\033[0m\n'
echo ">> Watch it: control panel > command library > binary drift + isolation > 1. heartbeat log"
