#!/usr/bin/env bash
# Delete the demo resource group and everything in it. Prompts first.
set -euo pipefail
RG="${RG:-rg-defdemo}"
echo "This will DELETE resource group '$RG' and every resource in it."
read -rp "Type the resource group name to confirm: " ans
if [[ "$ans" != "$RG" ]]; then echo "Name did not match. Aborted."; exit 1; fi
az group delete --name "$RG" --yes --no-wait
echo ">> Deletion started (no-wait)."
echo ">> Defender plans are subscription-scoped and are NOT removed by this."
echo ">> To stop plan billing: make disable-plans"
