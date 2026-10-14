#!/usr/bin/env bash
# Verify the FOUR prerequisites for Defender gated deployment, and say exactly what is missing.
#
# Per https://learn.microsoft.com/en-us/azure/defender-for-cloud/enablement-guide-runtime-gated :
#   - Defender sensor  WITH  Security Gating      (set per-cluster)
#   - Registry access  WITH  Security findings    (set on the Containers plan)
#   plus: AKS OIDC issuer enabled, and vulnerability scan results present for the image.
#
# Bicep covers three of these. "Security findings" cannot be enabled through Azure Policy and
# has no documented pricings extension name, so this script checks it and tells you where to
# toggle it. Run: make verify-gating
set -uo pipefail

RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
ok(){ printf '  \033[1;32m✔\033[0m %s\n' "$1"; }
bad(){ printf '  \033[1;31m✘\033[0m %s\n' "$1"; FAIL=1; }
warn(){ printf '  \033[1;33m!\033[0m %s\n' "$1"; }
FAIL=0

printf '\n\033[1;36m▶ Gated deployment prerequisites  (cluster=%s rg=%s)\033[0m\n\n' "$AKS" "$RG"

# --- plan level ---------------------------------------------------------
echo "Containers plan"
TIER="$(az security pricing show -n Containers --query pricingTier -o tsv 2>/dev/null)"
[[ "$TIER" == "Standard" ]] && ok "plan tier: Standard" || bad "plan tier is '${TIER:-unknown}', must be Standard"

EXT_JSON="$(az security pricing show -n Containers --query extensions -o json 2>/dev/null || echo '[]')"
ext_on(){ echo "$EXT_JSON" | python3 -c "
import json,sys
want=sys.argv[1]
try: x=json.load(sys.stdin) or []
except Exception: x=[]
print(next((str(e.get('isEnabled')).lower() for e in x if e.get('name')==want),'absent'))" "$1"; }

for e in ContainerRegistriesVulnerabilityAssessments:"Registry access [gating prereq]" \
         ContainerSensor:"Defender sensor [gating prereq]" \
         AgentlessDiscoveryForKubernetes:"Kubernetes API access/discovery" \
         AgentlessVmScanning:"Agentless scanning for machines"; do
  n="${e%%:*}"; label="${e#*:}"
  v="$(ext_on "$n")"
  [[ "$v" == "true" ]] && ok "$label ($n)" || bad "$label ($n) = $v"
done

# Security findings: the one Bicep cannot guarantee
SF="$(ext_on ContainerIntegrityContribution)"
case "$SF" in
  true)   ok "Security findings (ContainerIntegrityContribution)" ;;
  false)  bad "Security findings is DISABLED -> portal: Environment settings > Containers > Settings > Registry access > Security findings" ;;
  absent) warn "Security findings not visible as a pricing extension on this subscription.
      It may still be ON (it is on by default) - it is not settable via Azure Policy and has no
      documented extension name. CONFIRM IN THE PORTAL:
      Environment settings > Containers > Settings > Registry access > Security findings
      Then prove it end to end: push an image and check ACR > the image > Referrers for a
      signed findings artifact. No artifact = the gate sees every image as unscanned." ;;
esac

# --- cluster level ------------------------------------------------------
echo; echo "Cluster $AKS"
CL="$(az aks show -g "$RG" -n "$AKS" -o json 2>/dev/null)"
if [[ -z "$CL" ]]; then
  bad "cluster not found in $RG"
else
  q(){ echo "$CL" | python3 -c "
import json,sys,functools
d=json.load(sys.stdin)
cur=d
for k in sys.argv[1].split('.'):
    cur=(cur or {}).get(k) if isinstance(cur,dict) else None
print(cur)" "$1"; }
  [[ "$(q securityProfile.defender.securityGating.enabled)" == "True" ]] \
    && ok "Security Gating enabled on the cluster" \
    || bad "Security Gating NOT enabled (aks.bicep securityProfile.defender.securityGating; note it is intentionally off when defenderSensorViaHelm=true, the Helm chart ships its own admission controller)"
  [[ "$(q securityProfile.defender.securityMonitoring.enabled)" == "True" ]] \
    && ok "Defender sensor (securityMonitoring) enabled" \
    || warn "Defender sensor not enabled via the add-on - expected if you installed it with Helm (make sensor-helm)"
  [[ "$(q oidcIssuerProfile.enabled)" == "True" ]] \
    && ok "OIDC issuer enabled (required for AKS gating)" \
    || bad "OIDC issuer NOT enabled"
  ID="$(echo "$CL" | python3 -c "
import json,sys
d=json.load(sys.stdin)
i=((d.get('securityProfile') or {}).get('defender') or {}).get('securityGating') or {}
print(len(i.get('identities') or []))")"
  [[ "$ID" -gt 0 ]] && ok "gating identity attached ($ID) for pulling findings artifacts from ACR" \
                    || bad "no gating identity on securityGating.identities - the gate fails OPEN (REFERRER_STORE_FAILURE). Fix: make gating-identity"
fi

# --- Trusted Access: how Defender reaches into the cluster -------------------
# Defender pushes the gating and misconfiguration rules into the cluster as defender.microsoft.com
# objects through an AKS Trusted Access binding. Defender normally creates the bindings itself;
# without the policy operator no SecurityArtifactPolicy ever arrives and the gate only audits.
echo; echo "Trusted Access (Defender -> cluster)"
PRICING_ID="/subscriptions/$(az account show --query id -o tsv)/providers/Microsoft.Security/pricings/Containers"
TA_ROLES="$(az aks trustedaccess rolebinding list -g "$RG" --cluster-name "$AKS" \
  --query "[].roles[]" -o tsv 2>/dev/null || true)"
grep -q "microsoft-defender-policy-operator" <<<"$TA_ROLES" \
  && ok "microsoft-defender-policy-operator bound (Defender can push gating + misconfiguration rules)" \
  || bad "no Trusted Access binding with microsoft-defender-policy-operator - rules cannot reach the cluster. Fix: az aks trustedaccess rolebinding create -g $RG --cluster-name $AKS -n defender-policy --source-resource-id $PRICING_ID --roles Microsoft.Security/pricings/microsoft-defender-policy-operator"
grep -q "mdc-response-operator" <<<"$TA_ROLES" \
  && ok "mdc-response-operator bound (Defender XDR isolate / restrict pod)" \
  || warn "no Trusted Access binding with mdc-response-operator - XDR pod response actions cannot run. Fix: same command with -n defender-response --roles Microsoft.Security/pricings/mdc-response-operator"
TAGS="$(az aks show -g "$RG" -n "$AKS" --query "tags.ms_defender_e2e_discovery_exclude" -o tsv 2>/dev/null || true)"
[[ "$TAGS" == "true" ]] \
  && warn "tag ms_defender_e2e_discovery_exclude=true is set - it keeps Defender's discovery (which creates these bindings) away; it is meant for Arc clusters in AWS/GCP" \
  || true

# --- in-cluster (best effort) -------------------------------------------
if command -v kubectl >/dev/null 2>&1 && kubectl get ns >/dev/null 2>&1; then
  echo; echo "In-cluster"
  kubectl get validatingwebhookconfigurations -o name 2>/dev/null | grep -qi defender \
    && ok "Defender admission webhook registered" \
    || warn "no Defender validating webhook found yet (can take a while after enablement)"
  kubectl get pods -A 2>/dev/null | grep -q defender-admission-controller \
    && ok "defender-admission-controller pod present" \
    || warn "admission controller pod not found - if it is down, image gating does not run at all"
  # Step 4 lands as a workload-identity annotation on the controller's ServiceAccount.
  SA_CLIENT="$(kubectl get sa -A -o jsonpath='{range .items[?(@.metadata.name=="defender-admission-controller-serviceaccount")]}{.metadata.annotations.azure\.workload\.identity/client-id}{end}' 2>/dev/null || true)"
  [[ -n "$SA_CLIENT" ]] \
    && ok "admission controller ServiceAccount uses identity $SA_CLIENT" \
    || warn "admission controller ServiceAccount has no workload-identity client ID - it cannot read ACR (make gating-identity)"
  FAILS="$(kubectl -n kube-system logs deploy/defender-admission-controller --since=30m 2>/dev/null | grep -c REFERRER_STORE_FAILURE || true)"
  [[ "${FAILS:-0}" -eq 0 ]] \
    && ok "no REFERRER_STORE_FAILURE in the last 30 min" \
    || bad "$FAILS REFERRER_STORE_FAILURE in the last 30 min - images are admitted WITHOUT a verdict"
fi

echo
if [[ "$FAIL" -eq 0 ]]; then
  printf '\033[1;32m✔ no blocking gaps found. Remember: a rule still has to exist (make gating).\033[0m\n'
else
  printf '\033[1;31m✘ gaps above must be fixed or gated deployment will not enforce.\033[0m\n'; exit 1
fi
