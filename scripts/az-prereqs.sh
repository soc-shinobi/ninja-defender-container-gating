#!/usr/bin/env bash
# Azure CLI prerequisites for this lab: extensions + resource providers.
# Idempotent, safe to re-run. deploy.sh calls it; `make prereqs` runs it alone.
#
# BICEP is not an extension: `az bicep` is a core command group that downloads the Bicep CLI
# binary into ~/.azure/bin. az fetches it implicitly on the first .bicep/.bicepparam use, but
# that turns a deployment into a silent download - do it here where a failure is legible.
#
# EXTENSIONS (az CLI ships neither in core):
#   containerapp       every `az containerapp ...` call - build-push-app.sh, lab-park.sh,
#                      lab-start.sh, enable-aca-auth.sh, grant-controlpanel-access.sh
#   k8s-configuration  `az k8s-configuration flux show` - make flux-status, gate-denial-runbook
#
# Dynamic install would fetch them on first use, but only after an interactive prompt, so a
# fresh machine or a CI runner blocks or fails. Install them up front instead.
#
# PROVIDERS: Microsoft.KubernetesConfiguration is what makes infra/modules/flux.bicep
# deployable at all - the Flux extension and fluxConfiguration are its resource types.
# Microsoft.Kubernetes is deliberately NOT here: it is the Arc connectedClusters provider,
# and this lab runs a managed AKS cluster.
#   https://learn.microsoft.com/azure/azure-arc/kubernetes/tutorial-use-gitops-flux2#prerequisites
set -euo pipefail

echo ">> Azure CLI: $(az version --query '\"azure-cli\"' -o tsv 2>/dev/null || echo unknown)"

# No prompt when something still resolves through dynamic install (nested az calls, CI).
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

# Bicep CLI binary (core `az bicep`, NOT `az extension add`).
if BICEP_VER="$(az bicep version --only-show-errors 2>/dev/null)"; then
  echo "   bicep: ${BICEP_VER}"
else
  echo "   bicep: installing..."
  az bicep install --only-show-errors
fi

for ext in containerapp k8s-configuration; do
  if az extension show -n "$ext" -o none 2>/dev/null; then
    az extension update -n "$ext" -o none 2>/dev/null || true
    echo "   extension $ext: present"
  else
    echo "   extension $ext: installing..."
    az extension add -n "$ext" -o none
  fi
done

# Register providers the lab needs (no-op if already registered).
# Microsoft.OperationsManagement + Microsoft.Insights are what the AKS Container Insights
# add-on needs; without them the cluster write fails with MissingSubscriptionRegistration.
# Microsoft.KubernetesConfiguration is the Flux/GitOps one - without it the flux module
# fails the same way, and the failure names the provider, not Flux.
for ns in Microsoft.ContainerService Microsoft.App Microsoft.ContainerRegistry \
          Microsoft.CognitiveServices Microsoft.OperationalInsights Microsoft.Security \
          Microsoft.ManagedIdentity Microsoft.PolicyInsights \
          Microsoft.OperationsManagement Microsoft.Insights \
          Microsoft.KubernetesConfiguration; do
  az provider register --namespace "$ns" --wait >/dev/null 2>&1 || true
done
echo "   providers registered (or already were)"
