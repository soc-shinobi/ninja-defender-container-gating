#!/usr/bin/env bash
# Manual GitOps-equivalent bootstrap for DEPLOY_FLUX=false.
set -euo pipefail

RG="${RG:-rg-${NAME_PREFIX:-defdemo}}"
NAME_PREFIX="${NAME_PREFIX:-defdemo}"
AKS="${AKS:-${NAME_PREFIX}-aks}"

command -v kubectl >/dev/null || { echo "kubectl is required" >&2; exit 1; }
command -v envsubst >/dev/null || { echo "envsubst is required" >&2; exit 1; }

az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing -o none
ACR_LOGIN_SERVER="$(az acr list -g "$RG" --query '[0].loginServer' -o tsv)"
export ACR_LOGIN_SERVER

kubectl kustomize app/k8s \
  | envsubst '${ACR_LOGIN_SERVER}' \
  | kubectl apply -f -
kubectl -n demo-ops rollout status deployment/kubectl-runner --timeout=180s
