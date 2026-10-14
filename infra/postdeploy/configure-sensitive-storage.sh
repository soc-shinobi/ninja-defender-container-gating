#!/usr/bin/env bash
# Seed synthetic confidential data, disable Shared Key, then bind the public AKS web app
# to Blob through AKS workload identity. The running pod receives no storage credential.
set -euo pipefail

RG="${RG:-rg-${NAME_PREFIX:-defdemo}}"
NAME_PREFIX="${NAME_PREFIX:-defdemo}"
AKS="${AKS:-${NAME_PREFIX}-aks}"
NS="x-mdc-allowed"
SA="aks-webapp"
CONTAINER="sensitive-data"
BLOB="customers.json"
DATA_FILE="demo-data/fake-sensitive-data.json"
IDENTITY="${NAME_PREFIX}-aks-webapp-id"

[[ -f "$DATA_FILE" ]] || { echo "✘ missing $DATA_FILE" >&2; exit 1; }
ACCOUNT="$(az storage account list -g "$RG" \
  --query "[?tags.purpose=='aks-sensitive-demo'].name | [0]" -o tsv)"
[[ -n "$ACCOUNT" ]] || { echo "✘ sensitive demo storage account not found in $RG" >&2; exit 1; }
CLIENT_ID="$(az identity show -g "$RG" -n "$IDENTITY" --query clientId -o tsv)"
[[ -n "$CLIENT_ID" ]] || { echo "✘ workload identity $IDENTITY not found" >&2; exit 1; }

# Bootstrap only: use a storage key for the upload, then turn Shared Key authorization off.
# The application itself always uses its federated identity and Azure RBAC.
az storage account update -g "$RG" -n "$ACCOUNT" --allow-shared-key-access true -o none
disable_shared_key() {
  az storage account update -g "$RG" -n "$ACCOUNT" --allow-shared-key-access false -o none \
    || echo "⚠ failed to disable Shared Key on $ACCOUNT" >&2
}
trap disable_shared_key EXIT
KEY="$(az storage account keys list -g "$RG" -n "$ACCOUNT" --query '[0].value' -o tsv)"
# Re-enabling Shared Key is eventually consistent: the first upload right after the update
# can still get KeyBasedAuthenticationNotPermitted. Retry for up to ~2 minutes.
for attempt in $(seq 1 12); do
  az storage blob upload --account-name "$ACCOUNT" --account-key "$KEY" \
    --container-name "$CONTAINER" --name "$BLOB" --file "$DATA_FILE" \
    --overwrite true --content-type application/json -o none && break
  [[ $attempt -eq 12 ]] && { echo "✘ blob upload kept failing" >&2; exit 1; }
  echo "… Shared Key not active yet, retry $attempt/12 in 10s" >&2
  sleep 10
done
unset KEY
disable_shared_key
trap - EXIT

KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing \
  --file "$KUBECONFIG_FILE" -o none
K=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin")

"${K[@]}" -n "$NS" create serviceaccount "$SA" --dry-run=client -o yaml | "${K[@]}" apply -f -
"${K[@]}" -n "$NS" annotate serviceaccount "$SA" \
  azure.workload.identity/client-id="$CLIENT_ID" --overwrite
"${K[@]}" -n "$NS" create configmap sensitive-storage \
  --from-literal=STORAGE_ACCOUNT_URL="https://${ACCOUNT}.blob.core.windows.net" \
  --from-literal=STORAGE_CONTAINER="$CONTAINER" \
  --from-literal=STORAGE_BLOB="$BLOB" \
  --from-literal=STORAGE_POLL_SECONDS="30" \
  --dry-run=client -o yaml | "${K[@]}" apply -f -

"${K[@]}" -n "$NS" rollout restart deploy/webapp
"${K[@]}" -n "$NS" rollout status deploy/webapp --timeout=300s
printf '\033[1;32m✔ %s/%s retrieves fake sensitive Blob data using workload identity\033[0m\n' "$NS" "$SA"
