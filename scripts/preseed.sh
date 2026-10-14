#!/usr/bin/env bash
# Trigger the latency-bound demo items 2-3 days before a talk so they show
# results live. See docs/demo-story.md section 7 for the full table.
set -euo pipefail
: "${ACR_NAME:?set ACR_NAME (from .last-outputs.json)}"
RG="${RG:-rg-defdemo}"

echo ">> 1/3 Push the images so ACR image scanning has something to find."
bash scripts/build-push-app.sh || true

echo ">> 2/3 Hero deployment + Docker Hub bypass pod."
echo "   GitOps path: Flux is on by default and syncs app/k8s itself (make flux-status)."
echo "   Manual fallback (needs kubectl creds + envsubst):"
echo "     az aks get-credentials -g $RG -n ${NAME_PREFIX:-defdemo}-aks"
echo "     export ACR_LOGIN_SERVER=\$(az acr show -n $ACR_NAME --query loginServer -o tsv)"
echo "     kubectl kustomize app/k8s | envsubst '\${ACR_LOGIN_SERVER}' | kubectl apply -f -   # gate denies the hero image"
echo "     kubectl run bypass --image=nginx:1.19 -n x-mdc-allowed                                # out-of-scope namespace"

cat <<'EOF'

>> 3/3 Manual latency items (kick these now, they surface later):
   - GitHub connector + agentless code scanning ...... daily scan, ~15-60 min/run
   - DevOps posture for the two pipelines ............ every 8 hours
   - Attack path (ACA identity -> AKS) ............... up to 24 hours
   - GitHub issue -> PR -> resolved sync ............. up to 24 hours
   - Record fallback video of every live beat ........ do this last

See docs/demo-story.md sections 7 and 8 (open verifications) before the talk.
EOF
