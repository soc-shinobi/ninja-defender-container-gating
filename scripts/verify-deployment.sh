#!/usr/bin/env bash
# End-to-end checks. ARM success alone is not enough for this lab.
set -euo pipefail

RG="${RG:-rg-${NAME_PREFIX:-defdemo}}"
NAME_PREFIX="${NAME_PREFIX:-defdemo}"
AKS="${AKS:-${NAME_PREFIX}-aks}"
APP="${APP:-${NAME_PREFIX}-app}"
FAIL=0

ok() { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
bad() { printf '\033[1;31m✘ %s\033[0m\n' "$*" >&2; FAIL=1; }

AKS_STATE="$(az aks show -g "$RG" -n "$AKS" --query provisioningState -o tsv 2>/dev/null || true)"
[[ "$AKS_STATE" == "Succeeded" ]] && ok "AKS provisioning succeeded" || bad "AKS state: ${AKS_STATE:-missing}"

APP_STATE="$(az containerapp show -g "$RG" -n "$APP" --query properties.provisioningState -o tsv 2>/dev/null || true)"
[[ "$APP_STATE" == "Succeeded" ]] && ok "Container App provisioning succeeded" || bad "Container App state: ${APP_STATE:-missing}"

IMAGE="$(az containerapp show -g "$RG" -n "$APP" --query 'properties.template.containers[0].image' -o tsv 2>/dev/null || true)"
PORT="$(az containerapp show -g "$RG" -n "$APP" --query 'properties.configuration.ingress.targetPort' -o tsv 2>/dev/null || true)"
if [[ "$IMAGE" == *@sha256:* && "$PORT" == "8080" ]]; then
  ok "control panel uses an immutable ACR digest on port 8080"
else
  bad "control panel is not ready (image=$IMAGE targetPort=$PORT); run: make app"
fi

FQDN="$(az containerapp show -g "$RG" -n "$APP" --query 'properties.configuration.ingress.fqdn' -o tsv 2>/dev/null || true)"
if [[ -n "$FQDN" ]] && curl -fsS --max-time 30 "https://${FQDN}/healthz" | grep -qx 'ok'; then
  ok "public health endpoint"
else
  bad "public health endpoint failed"
fi

az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing -o none 2>/dev/null || true
if kubectl -n demo-ops rollout status deployment/kubectl-runner --timeout=300s >/dev/null 2>&1; then
  ok "kubectl runner is available"
else
  bad "kubectl runner is unavailable"
fi

if kubectl -n x-mdc-allowed get serviceaccount aks-webapp \
  -o jsonpath='{.metadata.annotations.azure\.workload\.identity/client-id}' 2>/dev/null | grep -q . \
  && kubectl -n x-mdc-allowed get configmap sensitive-storage >/dev/null 2>&1; then
  ok "AKS web app sensitive Blob workload identity is configured"
else
  bad "AKS web app sensitive Blob connection is not configured; run: make sensitive-storage"
fi

AKS_WEBAPP_HOST="$(kubectl -n x-mdc-allowed get service webapp \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)"
if [[ -z "$AKS_WEBAPP_HOST" ]]; then
  AKS_WEBAPP_HOST="$(kubectl -n x-mdc-allowed get service webapp \
    -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || true)"
fi
BLOB_OK=false
if [[ -n "$AKS_WEBAPP_HOST" ]]; then
  for _ in $(seq 1 30); do
    if curl -fsS --max-time 10 "http://${AKS_WEBAPP_HOST}/api/connections" 2>/dev/null \
      | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["blob"]["status"] == "ok"' \
      2>/dev/null; then
      BLOB_OK=true
      break
    fi
    sleep 10
  done
fi
[[ "$BLOB_OK" == "true" ]] \
  && ok "public AKS web app retrieved fake sensitive Blob data" \
  || bad "public AKS web app did not report a healthy Blob connection"

PRINCIPAL="$(az containerapp show -g "$RG" -n "$APP" --query 'identity.userAssignedIdentities.*.principalId | [0]' -o tsv 2>/dev/null || true)"
AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv 2>/dev/null || true)"
WRITER="$(az role assignment list --scope "$AKS_ID/namespaces/demo-ops" --query "[?principalId=='$PRINCIPAL' && roleDefinitionName=='Azure Kubernetes Service RBAC Writer'].roleDefinitionName | [0]" -o tsv 2>/dev/null || true)"
[[ "$WRITER" == "Azure Kubernetes Service RBAC Writer" ]] && ok "panel namespace Writer role" || bad "panel namespace Writer role missing"

POLICY="$(az aks show -g "$RG" -n "$AKS" --query 'addonProfiles.azurePolicy.enabled' -o tsv 2>/dev/null || true)"
if [[ "${DEPLOY_AZURE_POLICY:-false}" == "true" || "$POLICY" != "true" ]]; then
  ok "Azure Policy add-on matches preference"
else
  bad "Azure Policy add-on is unexpectedly enabled"
fi

exit "$FAIL"
