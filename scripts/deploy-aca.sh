#!/usr/bin/env bash
# Deploy only Azure Container Apps. On the specific regional-capacity failure, retry in a
# fallback region under a different managed-environment name. Core resources are untouched.
set -euo pipefail

RG="${RG:-rg-${NAME_PREFIX:-defdemo}}"
NAME_PREFIX="${NAME_PREFIX:-defdemo}"
PRIMARY_LOCATION="${ACA_LOCATION:-swedencentral}"
PRIMARY_ENV="${ACA_ENV_NAME:-${NAME_PREFIX}-aca-env}"
FALLBACK_LOCATION="${ACA_FALLBACK_LOCATION:-norwayeast}"
FALLBACK_ENV="${ACA_FALLBACK_ENV_NAME:-${NAME_PREFIX}-aca-env-noe}"
ERROR_FILE=".last-deploy-error.log"

export RG NAME_PREFIX

deploy_aca() {
  export ACA_LOCATION="$1" ACA_ENV_NAME="$2"
  local deployment="aca-${ACA_LOCATION}-$(date +%Y%m%d-%H%M%S)"
  echo ">> ACA environment: $ACA_ENV_NAME   location: $ACA_LOCATION"
  az deployment group create \
    --resource-group "$RG" \
    --name "$deployment" \
    --parameters infra/aca.bicepparam \
    --query properties.outputs -o json \
    2> >(tee "$ERROR_FILE" >&2) | tee .last-aca-outputs.json
}

# A Container App cannot move regions in place. Refuse an implicit destructive move.
if CURRENT_LOCATION="$(az containerapp show -g "$RG" -n "${NAME_PREFIX}-app" --query location -o tsv 2>/dev/null)" \
  && [[ -n "$CURRENT_LOCATION" && "${CURRENT_LOCATION,,}" != "${PRIMARY_LOCATION,,}" ]]; then
  echo "Container App ${NAME_PREFIX}-app already exists in $CURRENT_LOCATION; refusing to move/delete it automatically." >&2
  echo "Set ACA_LOCATION=$CURRENT_LOCATION to update it, or delete it explicitly before a regional move." >&2
  exit 1
fi

if deploy_aca "$PRIMARY_LOCATION" "$PRIMARY_ENV"; then
  exit 0
fi

if ! grep -Eq 'ManagedEnvironmentNoAvailableCapacityInRegion|NoAvailableCapacityInRegion' "$ERROR_FILE"; then
  echo "ACA deployment failed for a non-capacity reason; regional fallback was not attempted." >&2
  exit 1
fi

if [[ "${PRIMARY_LOCATION,,}" == "${FALLBACK_LOCATION,,}" ]]; then
  echo "ACA primary and fallback locations are identical; cannot fall back." >&2
  exit 1
fi

echo ">> ACA capacity unavailable in $PRIMARY_LOCATION; falling back to $FALLBACK_LOCATION"
deploy_aca "$FALLBACK_LOCATION" "$FALLBACK_ENV"
