#!/usr/bin/env bash
# Gated deployment, step 4: tell the AKS add-on WHICH identity reads the findings from ACR.
#
# Microsoft's guide (gated-deployment-infrastructure-as-code#configure-the-managed-identity):
#   1. a user-assigned identity                       -> workload.bicep (gatingIdentity)
#   2. AcrPull on every ACR the cluster uses           -> workload.bicep (gatingAcrPull)
#   3. a federated credential: AKS OIDC issuer,
#      system:serviceaccount:kube-system:defender-admission-controller-serviceaccount,
#      audience api://AzureADTokenExchange             -> workload.bicep (gatingFic)
#   4. that identity in securityProfile.defender.securityGating.identities  -> THIS SCRIPT
#
# Without step 4 the admission controller has no registry credentials. It cannot resolve the
# image, logs "REFERRER_STORE_FAILURE: could not resolve descriptor for a subject from any
# stores", and FAILS OPEN - every pod is admitted, deny rule or not. Nothing on screen says so.
#
# Why a script and not the Bicep: the resource provider rejected "identities" in the cluster
# body in swedencentral (2025-05-02-preview and 2026-02-02-preview, UnmarshalError: unknown
# field). Here it is a read-modify-write of the existing cluster on a GA api-version, after
# the cluster exists, so it can never fail the cluster deployment. Safe to re-run: an identity
# that is already attached is left alone.
#
# Helm sensor (DEFENDER_SENSOR_VIA_HELM=true): the add-on gating is off and the chart ships
# its own admission controller, so this script skips.
set -euo pipefail
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
GATING_ID="${GATING_ID:-${NAME_PREFIX:-defdemo}-gating-id}"
SA_NS="${DEFENDER_NAMESPACE:-kube-system}"
SA_NAME="defender-admission-controller-serviceaccount"
# GA version that documents securityGating.identities. Override if the region lags.
API="${AKS_GATING_API_VERSION:-2026-07-01}"

ok(){   printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
warn(){ printf '\033[1;33m! %s\033[0m\n' "$*"; }
die(){  printf '\033[1;31m✘ %s\033[0m\n' "$*" >&2; exit 1; }
step(){ printf '\033[1;36m▶ %s\033[0m\n' "$*"; }

AKS_ID="$(az aks show -g "$RG" -n "$AKS" --query id -o tsv 2>/dev/null)" \
  || die "cluster $AKS not found in $RG"
URL="https://management.azure.com${AKS_ID}?api-version=${API}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
az rest --method get --url "$URL" -o json > "$TMP/cluster.json"

GATING_ON="$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(((d['properties'].get('securityProfile') or {}).get('defender') or {}).get('securityGating',{}).get('enabled'))" "$TMP/cluster.json")"
if [[ "$GATING_ON" != "True" ]]; then
  warn "securityGating is not enabled on $AKS (Helm sensor, or gating off) - nothing to attach"
  exit 0
fi

# ---- the identity and its prerequisites (steps 1-3) -------------------------
step "gating identity $GATING_ID"
ID_JSON="$(az identity show -g "$RG" -n "$GATING_ID" -o json 2>/dev/null)" \
  || die "identity $GATING_ID not found in $RG (workload.bicep creates it)"
idf(){ python3 -c "import json,sys;print(json.loads(sys.argv[1])[sys.argv[2]])" "$ID_JSON" "$1"; }
CLIENT_ID="$(idf clientId)"; OBJECT_ID="$(idf principalId)"; ID_RES="$(idf id)"
ok "clientId $CLIENT_ID"

ACR_SERVER="${ACR_LOGIN_SERVER:-$(az acr list -g "$RG" --query '[0].loginServer' -o tsv)}"
[[ -n "$ACR_SERVER" ]] || die "no ACR in $RG; set ACR_LOGIN_SERVER"
ACR_ID="$(az acr list -g "$RG" --query "[?loginServer=='$ACR_SERVER'].id | [0]" -o tsv)"
if [[ -n "$ACR_ID" && -n "$(az role assignment list --assignee "$OBJECT_ID" --scope "$ACR_ID" \
      --query "[?roleDefinitionName=='AcrPull'].id | [0]" -o tsv)" ]]; then
  ok "AcrPull on $ACR_SERVER"
else
  warn "no AcrPull for $GATING_ID on $ACR_SERVER - the gate will still fail to read findings"
fi

# The raw REST body spells it issuerURL; az aks show normalises it to issuerUrl. Accept both.
ISSUER="$(python3 -c "import json,sys;o=json.load(open(sys.argv[1]))['properties'].get('oidcIssuerProfile') or {};print(o.get('issuerURL') or o.get('issuerUrl') or '')" "$TMP/cluster.json")"
[[ -n "$ISSUER" ]] || die "OIDC issuer not enabled on $AKS (oidcIssuerProfile.enabled)"
SUBJECT="system:serviceaccount:${SA_NS}:${SA_NAME}"
FIC="$(az identity federated-credential list -g "$RG" --identity-name "$GATING_ID" \
  --query "[?subject=='$SUBJECT' && issuer=='$ISSUER'].name | [0]" -o tsv)"
if [[ -n "$FIC" ]]; then
  ok "federated credential $FIC ($SUBJECT)"
else
  step "creating the federated credential ($SUBJECT)"
  az identity federated-credential create -g "$RG" --identity-name "$GATING_ID" \
    --name defender-admission-controller --issuer "$ISSUER" --subject "$SUBJECT" \
    --audiences api://AzureADTokenExchange -o none
  ok "federated credential created"
fi

# ---- step 4: securityGating.identities -------------------------------------
ATTACHED="$(python3 - "$TMP/cluster.json" "$OBJECT_ID" "$ID_RES" "$ACR_SERVER" <<'PY'
import json, sys
path, oid, rid, acr = sys.argv[1:]
d = json.load(open(path))
ids = d["properties"]["securityProfile"]["defender"]["securityGating"].get("identities") or []
hit = any(i.get("azureContainerRegistry", "").lower() == acr.lower()
          and ((i.get("identity") or {}).get("objectId") == oid
               or (i.get("identity") or {}).get("resourceId", "").lower() == rid.lower())
          for i in ids)
print("yes" if hit else "no")
PY
)"
if [[ "$ATTACHED" == "yes" ]]; then
  ok "already attached to securityGating.identities for $ACR_SERVER"
else
  step "attaching $GATING_ID to securityGating.identities for $ACR_SERVER (api $API)"
  python3 - "$TMP/cluster.json" "$CLIENT_ID" "$OBJECT_ID" "$ID_RES" "$ACR_SERVER" > "$TMP/put.json" <<'PY'
import json, sys
path, cid, oid, rid, acr = sys.argv[1:]
d = json.load(open(path))
gating = d["properties"]["securityProfile"]["defender"]["securityGating"]
ids = [i for i in (gating.get("identities") or [])
       if i.get("azureContainerRegistry", "").lower() != acr.lower()]
ids.append({"azureContainerRegistry": acr,
            "identity": {"clientId": cid, "objectId": oid, "resourceId": rid}})
gating["identities"] = ids
# Read-only on PUT; sending them back only invites a validation error.
for k in ("provisioningState", "powerState", "maxAgentPools", "fqdn", "azurePortalFQDN",
          "privateFQDN", "currentKubernetesVersion", "resourceUID"):
    d["properties"].pop(k, None)
for p in d["properties"].get("agentPoolProfiles", []):
    for k in ("provisioningState", "powerState", "currentOrchestratorVersion", "nodeImageVersion",
              "eTag"):
        p.pop(k, None)
for k in ("id", "name", "type", "systemData", "eTag"):
    d.pop(k, None)
json.dump(d, sys.stdout)
PY
  if ! az rest --method put --url "$URL" --body @"$TMP/put.json" -o none 2> "$TMP/err.txt"; then
    cat "$TMP/err.txt" >&2
    die "the resource provider refused the update. If it says unknown field \"identities\", the
   region does not take it yet on $API: retry with AKS_GATING_API_VERSION=<newer>, or use the
   Helm sensor (make sensor-helm), which does not need this field."
  fi
  step "waiting for the cluster update to finish"
  az aks wait -g "$RG" -n "$AKS" --updated --timeout 1800 >/dev/null
  ok "attached"
fi

# ---- proof: the admission controller's ServiceAccount carries the client ID ----------
if command -v kubectl >/dev/null 2>&1; then
  KUBECONFIG_FILE="${KUBECONFIG:-$HOME/.kube/config}"
  az aks get-credentials -g "$RG" -n "$AKS" --admin --overwrite-existing \
    --file "$KUBECONFIG_FILE" -o none 2>/dev/null || true
  K=(kubectl --kubeconfig "$KUBECONFIG_FILE" --context "${AKS}-admin")
  SA_CLIENT=""
  for _ in $(seq 1 30); do
    SA_CLIENT="$("${K[@]}" -n "$SA_NS" get sa "$SA_NAME" \
      -o jsonpath='{.metadata.annotations.azure\.workload\.identity/client-id}' 2>/dev/null || true)"
    [[ -n "$SA_CLIENT" ]] && break
    sleep 10
  done
  if [[ "$SA_CLIENT" == "$CLIENT_ID" ]]; then
    ok "$SA_NS/$SA_NAME uses client ID $SA_CLIENT"
  else
    warn "$SA_NS/$SA_NAME client-id annotation is '${SA_CLIENT:-<none>}' (expected $CLIENT_ID);"
    warn "the add-on reconciles it - re-check in a few minutes with make verify-gating"
  fi
fi

echo
echo ">> Gating can only judge images Defender has scanned: the findings artifact appears on the"
echo "   image in ACR (Referrers tab) a few hours after the first push of a new registry."
echo ">> Proof it works: the admission controller logs stop showing REFERRER_STORE_FAILURE:"
echo "   kubectl -n $SA_NS logs deploy/defender-admission-controller --since=10m | grep -c REFERRER_STORE_FAILURE"
