#!/usr/bin/env bash
# Install the Defender for Containers sensor via Helm instead of the AKS add-on.
#
# WHY: binary drift *blocking* (and antimalware) require the Helm-provisioned
# sensor (>= 0.10.2). The AKS add-on path gives drift *detection* only. Use this
# when you want the "flip drift to block, second attempt fails" demo beat.
#
# ORDER MATTERS (see Pit's gated-deployment post): the cluster must be excluded
# from Defender's automatic sensor provisioning BEFORE the sensor is auto-deployed,
# otherwise you end up with two sensors. Deploy with
#   param defenderSensorViaHelm = true
# in infra/main.bicepparam, which sets the exclusion tag and disables the add-on
# sensor at creation time, then run this script.
set -euo pipefail

RG="${RG:-rg-defdemo}"
AKS="${AKS:-defdemo-aks}"
SUB_ID="$(az account show --query id -o tsv)"
LOCATION="$(az aks show -g "$RG" -n "$AKS" --query location -o tsv)"

echo ">> Checking exclusion tag on $AKS (must be set before auto-provisioning)"
TAG="$(az aks show -g "$RG" -n "$AKS" --query "tags.ms_defender_container_exclude_sensors" -o tsv 2>/dev/null || true)"
if [[ "$TAG" != "true" ]]; then
  echo "!! Exclusion tag missing. Either redeploy with defenderSensorViaHelm=true, or"
  echo "   if the add-on sensor is NOT yet deployed, set it now:"
  echo "   az tag update --resource-id \$(az aks show -g $RG -n $AKS --query id -o tsv) --operation merge --tags ms_defender_container_exclude_sensors=true"
  exit 1
fi

echo ">> Getting cluster credentials"
KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing \
  --file "$KUBECONFIG_FILE" >/dev/null
# Pin file AND context: whichever context the shell was already on is not this cluster.
KCTL=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin")

# Leftovers from an add-on deployment collide with the chart's own objects. Microsoft
# documents exactly this list; removing the profile does not take them with it.
# https://learn.microsoft.com/azure/defender-for-cloud/deploy-helm

# NAMESPACE: 'mdc' for a standard AKS cluster. AKS AUTOMATIC is the exception - there the
# sensor must go into kube-system, and gated deployment only works that way.
NAMESPACE="${DEFENDER_NAMESPACE:-mdc}"
# Leftover cleanup only on the FIRST install. Once the release exists these CRDs are the
# chart's own: deleting them on a re-run would take every synced Defender policy with them.
if helm status defender-k8s --kubeconfig "$KUBECONFIG_FILE" --kube-context "${AKS}-admin" \
     --namespace "$NAMESPACE" >/dev/null 2>&1; then
  echo ">> Release defender-k8s already installed - skipping add-on leftover cleanup"
else
  echo ">> Removing leftovers from any previous add-on deployment"
  for crd in policies policytemplates runtimepolicies securityartifactpolicies; do
    "${KCTL[@]}" delete "crd/${crd}.defender.microsoft.com" --ignore-not-found >/dev/null || true
  done
  # Microsoft's list stops at the admission-controller roles. The add-on also leaves the VAP
  # role, the collector/publisher roles and its validating webhook behind, and Helm refuses to
  # adopt any object it did not create ("invalid ownership metadata").
  for cr in defender-admission-controller-cluster-role \
            defender-admission-controller-resource-cluster-role \
            defender-admission-controller-vap-cluster-role \
            microsoft-defender-collector-role \
            microsoft-defender-publisher-role; do
    "${KCTL[@]}" delete clusterrole "$cr" --ignore-not-found >/dev/null || true
  done
  for crb in defender-admission-controller-cluster-role-binding \
             defender-admission-controller-cluster-resource-role-binding \
             defender-admission-controller-vap-cluster-role-binding \
             microsoft-defender-collector-role-binding \
             microsoft-defender-publisher-role-binding; do
    "${KCTL[@]}" delete clusterrolebinding "$crb" --ignore-not-found >/dev/null || true
  done
  "${KCTL[@]}" delete validatingwebhookconfiguration \
    defender-admission-controller.kube-system.svc --ignore-not-found >/dev/null || true
fi

# Pinned chart (latest). Chart and sensor are versioned separately: chart 0.11.4 ships sensor 0.11.7
# (see the Defender sensor change log); 0.11.5 ships sensor 0.11.9. Override to test another.
#   helm show chart oci://mcr.microsoft.com/azuredefender/microsoft-defender-for-containers --version <v>
CHART_VERSION="${DEFENDER_CHART_VERSION:-0.11.5}"

# Antimalware needs sensor >= 0.10.x and costs extra cluster resources, so it is opt-in.
ANTIMALWARE_ARGS=()
if [[ "${ENABLE_ANTIMALWARE:-false}" == "true" ]]; then
  ANTIMALWARE_ARGS=(--set microsoft-defender-for-containers-sensor.antimalwareCollector.enabled=true)
fi

echo ">> Installing Defender for Containers via Helm into namespace $NAMESPACE"
helm upgrade --install defender-k8s \
  oci://mcr.microsoft.com/azuredefender/microsoft-defender-for-containers \
  --version "$CHART_VERSION" \
  --kubeconfig "$KUBECONFIG_FILE" --kube-context "${AKS}-admin" \
  --create-namespace --namespace "$NAMESPACE" \
  "${ANTIMALWARE_ARGS[@]}" \
  --set defender-admission-controller.enableMisconfigurationPolicies=true \
  --set global.cloudIdentifiers.Azure.subscriptionId="$SUB_ID" \
  --set global.cloudIdentifiers.Azure.resourceGroupName="$RG" \
  --set global.cloudIdentifiers.Azure.clusterName="$AKS" \
  --set global.cloudIdentifiers.Azure.region="$LOCATION"

echo ">> Sensor pods:"
"${KCTL[@]}" get pods -n "$NAMESPACE"
helm list --kubeconfig "$KUBECONFIG_FILE" --kube-context "${AKS}-admin" --namespace "$NAMESPACE"
echo ">> Done. Drift BLOCKING and antimalware are now available. Configure the drift rule"
echo "   action 'Drift detection blocking' in Environment settings > Containers drift policy."
