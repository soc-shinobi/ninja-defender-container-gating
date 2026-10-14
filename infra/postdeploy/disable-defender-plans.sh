#!/usr/bin/env bash
# Revert the Defender for Cloud plans this lab enabled back to Free.
# Stops billing without deleting any workload resources.
set -euo pipefail
for plan in CloudPosture Containers AI StorageAccounts; do
  az security pricing create -n "$plan" --tier Free >/dev/null 2>&1 \
    && echo "$plan -> Free" \
    || echo "$plan -> could not change (check permissions / plan name)"
done
echo ">> Done. Re-enable with: make deploy (or re-run the Bicep)."
