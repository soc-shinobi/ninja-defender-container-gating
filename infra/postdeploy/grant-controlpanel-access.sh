#!/usr/bin/env bash
# Grant the Container App control panel EXEC rights, scoped to one namespace.
#
# Bicep already grants "Azure Kubernetes Service RBAC Reader" at CLUSTER scope (read-only,
# every namespace - the overview and pod list need that). This script adds the one permission
# Bicep cannot express: "Azure Kubernetes Service RBAC Writer" scoped to
# <clusterId>/namespaces/demo-ops, which is what allows pods/exec into the kubectl runner.
# Namespace-scoped assignments target a path under the cluster resource, not an ARM resource,
# so they have to be created with the CLI.
#
# Least privilege on purpose: read everywhere, exec in exactly one namespace, never
# cluster-admin. What kubectl can DO once inside the runner is a second, separate layer -
# the runner's Kubernetes ServiceAccount in app/k8s/base/30-kubectl-runner.yaml.
set -euo pipefail

# needs the `containerapp` CLI extension; `make deploy` installs it (scripts/az-prereqs.sh).
# run standalone on a fresh machine, let az fetch it instead of prompting.
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"
NS="${RUNNER_NAMESPACE:-demo-ops}"
ROLE="Azure Kubernetes Service RBAC Writer"

AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv)"
PRINCIPAL="$(az containerapp show -g "$RG" -n "$APP" \
  --query "identity.userAssignedIdentities.*.principalId | [0]" -o tsv)"

if [[ -z "$PRINCIPAL" || "$PRINCIPAL" == "null" ]]; then
  echo "✘ could not resolve the Container App's user-assigned identity principalId" >&2
  exit 1
fi

printf '\033[1;36m▶ %s\n  assignee : %s\n  scope    : %s/namespaces/%s\033[0m\n' \
  "$ROLE" "$PRINCIPAL" "$AKS_ID" "$NS"

az role assignment create \
  --role "$ROLE" \
  --assignee-object-id "$PRINCIPAL" \
  --assignee-principal-type ServicePrincipal \
  --scope "$AKS_ID/namespaces/$NS" \
  -o none && printf '\033[1;32m✔ granted\033[0m\n' \
  || printf '\033[1;33m! assignment may already exist\033[0m\n'

# The overview lists NODES, and the Azure RBAC Reader role does not cover the core nodes
# resource (it stops at metrics.k8s.io/nodes). Bind that single read permission in
# Kubernetes RBAC instead of widening the Azure role to Cluster Admin.
if command -v kubectl >/dev/null 2>&1; then
  printf '\033[1;36m▶ ClusterRole panel-node-reader (nodes: get,list)\033[0m\n'
  KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
  az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing \
    --file "$KUBECONFIG_FILE" -o none 2>/dev/null || true
  # Pin file AND context: whatever context the shell was already on is not this cluster.
  sed "s/PANEL_PRINCIPAL_ID/$PRINCIPAL/" "$(dirname "$0")/../../app/k8s/05-panel-node-reader.yaml" \
    | kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin" apply -f - \
    && printf '\033[1;32m✔ node read granted\033[0m\n' \
    || printf '\033[1;33m! could not apply the node-reader binding (need cluster-admin kubeconfig)\033[0m\n'
  # The GitOps blade reads Flux custom resources, which the Azure Reader role does not cover.
  printf '\033[1;36m▶ ClusterRole panel-flux-reader (Flux objects: get,list)\033[0m\n'
  sed "s/PANEL_PRINCIPAL_ID/$PRINCIPAL/" "$(dirname "$0")/../../app/k8s/06-panel-flux-reader.yaml" \
    | kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin" apply -f - \
    && printf '\033[1;32m✔ flux read granted\033[0m\n' \
    || printf '\033[1;33m! could not apply the flux-reader binding (need cluster-admin kubeconfig)\033[0m\n'
else
  echo "! kubectl not found - apply app/k8s/05-panel-node-reader.yaml and 06-panel-flux-reader.yaml"
  echo "  yourself (replace PANEL_PRINCIPAL_ID with $PRINCIPAL)"
fi

echo
echo ">> Verify from the control panel: open it and run  kubectl get pods -A"
echo ">> Note: every exec is audited. Look for it in CloudAuditEvents - the control panel and"
echo "   an attacker look identical from the cluster's side, which is the runtime talking point."
