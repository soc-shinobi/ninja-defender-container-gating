#!/usr/bin/env bash
# Defender or subscription policy can turn the AKS Azure Policy add-on back on. Reconcile it
# to the explicit deployment preference after the cluster write finishes.
set -euo pipefail

RG="${RG:-rg-${NAME_PREFIX:-defdemo}}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
DESIRED="${DEPLOY_AZURE_POLICY:-false}"
CURRENT="$(az aks show -g "$RG" -n "$AKS" --query 'addonProfiles.azurePolicy.enabled' -o tsv 2>/dev/null || true)"

if [[ "$DESIRED" == "true" ]]; then
  [[ "$CURRENT" == "true" ]] || az aks enable-addons -g "$RG" -n "$AKS" --addons azure-policy -o none
else
  [[ "$CURRENT" != "true" ]] || az aks disable-addons -g "$RG" -n "$AKS" --addons azure-policy -o none
fi

CURRENT="$(az aks show -g "$RG" -n "$AKS" --query 'addonProfiles.azurePolicy.enabled' -o tsv 2>/dev/null || true)"
echo ">> Azure Policy desired=$DESIRED actual=${CURRENT:-false}"
