#!/usr/bin/env bash
# Park or start the lab (AKS + Container App) to keep lab costs low while
# keeping everything deployed.
#
#   stop  (default):
#     AKS: az aks stop (deallocates the nodes), then delete the 'kubernetes' /
#          'kubernetes-internal' load balancer(s) and the SERVICE public IPs in
#          the node resource group. The cluster's managed EGRESS / outbound IP(s)
#          are kept on purpose (read from the cluster's effectiveOutboundIPs,
#          never guessed by name), so outbound allow-lists survive. AKS recreates
#          the load balancer and re-allocates service IPs on the next start.
#     ACA: scale the Container App to minReplicas 0 (scales to zero when idle,
#          cold-starts on the next request). Set PARK_ACA=false to skip.
#   start:
#     AKS: az aks start (LB + service IPs come back; NEW addresses).
#     ACA: minReplicas back to 1.
#
# Idempotent: already-stopped cluster, missing LB, no orphaned PIPs, or a missing
# Container App are all skipped cleanly. Never deletes a PIP still attached.
#
# Needs: az CLI logged in; RBAC = Azure Kubernetes Service Contributor on the
# cluster, Network Contributor (or Contributor) on the NODE resource group
# (MC_<rg>_<aks>_<region>) where the LB and PIPs live, and Contributor on the
# lab RG for the Container App.
set -euo pipefail

ACTION="${1:-stop}"
RG="${RG:-rg-defdemo}"
AKS="${AKS:-${NAME_PREFIX:-defdemo}-aks}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"
PARK_ACA="${PARK_ACA:-true}"

# the containerapp extension is auto-installed on first use (CI runners, fresh machines)
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

c() { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }   # c <ansi> <text>

if ! az aks show -g "$RG" -n "$AKS" -o none 2>/dev/null; then
  c '1;31' "✘ AKS cluster $AKS not found in $RG"; exit 1
fi

STATE="$(az aks show -g "$RG" -n "$AKS" --query powerState.code -o tsv)"
NODE_RG="$(az aks show -g "$RG" -n "$AKS" --query nodeResourceGroup -o tsv)"
c '1;36' "▶ $ACTION  cluster=$AKS  app=$APP  rg=$RG  nodeRG=$NODE_RG  state=$STATE"

aca_scale() {   # aca_scale <min>
  local min="$1"
  if [[ "$PARK_ACA" != "true" ]]; then c '1;33' "ℹ PARK_ACA=false - Container App untouched"; return; fi
  if ! az containerapp show -g "$RG" -n "$APP" -o none 2>/dev/null; then
    c '1;33' "ℹ Container App $APP not found - skipping"; return
  fi
  c '1;36' "▶ Container App $APP: minReplicas $min"
  az containerapp update -g "$RG" -n "$APP" --min-replicas "$min" --max-replicas 1 -o none
  if [[ "$min" == "0" ]]; then c '1;32' "✔ $APP scales to zero when idle"; else c '1;32' "✔ $APP running (1 replica)"; fi
}

case "$ACTION" in
  start)
    if [[ "$STATE" == "Running" ]]; then
      c '1;33' "ℹ cluster already running - skipping az aks start"
    else
      c '1;36' "▶ az aks start (LB + service IPs are recreated by AKS; new addresses)"
      az aks start -g "$RG" -n "$AKS" -o none
      c '1;32' "✔ cluster running"
    fi
    aca_scale 1
    ;;

  stop)
    # 1) egress IPs to KEEP - from the cluster, not by name
    mapfile -t KEEP < <(az aks show -g "$RG" -n "$AKS" \
      --query "networkProfile.loadBalancerProfile.effectiveOutboundIPs[].id" -o tsv)
    c '1;36' "▶ egress/outbound IP(s) to keep: ${#KEEP[@]}"
    for k in "${KEEP[@]}"; do echo "    keep  ${k##*/}"; done

    # 2) stop the cluster (deallocates node VMs)
    if [[ "$STATE" == "Stopped" ]]; then
      c '1;33' "ℹ cluster already stopped - skipping az aks stop"
    else
      c '1;36' "▶ az aks stop"
      az aks stop -g "$RG" -n "$AKS" -o none
      c '1;32' "✔ cluster stopped"
    fi

    # 3) delete the AKS-managed load balancer(s) - AKS recreates them on start
    mapfile -t LBS < <(az network lb list -g "$NODE_RG" \
      --query "[?name=='kubernetes' || name=='kubernetes-internal'].name" -o tsv)
    if [[ ${#LBS[@]} -eq 0 ]]; then
      c '1;33' "ℹ no kubernetes load balancer present - skipping"
    fi
    for lb in "${LBS[@]}"; do
      c '1;36' "▶ delete load balancer $lb"
      az network lb delete -g "$NODE_RG" -n "$lb"
      c '1;32' "✔ deleted $lb"
    done

    # 4) delete orphaned service PIPs - never the egress IPs, never anything still attached
    DELETED=0; KEPT=0
    while IFS= read -r pip; do
      [[ -z "$pip" ]] && continue
      name="${pip##*/}"
      if printf '%s\n' "${KEEP[@]}" | grep -qx "$pip"; then
        echo "    keep  $name  (egress)"; KEPT=$((KEPT+1)); continue
      fi
      attached="$(az network public-ip show --ids "$pip" --query "ipConfiguration.id" -o tsv 2>/dev/null || true)"
      if [[ -n "$attached" ]]; then
        echo "    keep  $name  (still attached: ${attached##*/})"; KEPT=$((KEPT+1)); continue
      fi
      c '1;36' "▶ delete public IP $name"
      az network public-ip delete --ids "$pip"
      DELETED=$((DELETED+1))
    done < <(az network public-ip list -g "$NODE_RG" --query "[].id" -o tsv)
    c '1;32' "✔ AKS parked: nodes deallocated, LB removed, $DELETED service IP(s) deleted, $KEPT IP(s) kept"

    # 5) Container App to zero
    aca_scale 0
    ;;

  *)
    c '1;31' "✘ unknown action '$ACTION' (use: stop | start)"; exit 1 ;;
esac
