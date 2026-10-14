#!/usr/bin/env bash
# Build the deliberately vulnerable demo apps and push them to ACR as BOTH teams'
# images, then point the Container App at the digest that was just pushed.
#
# TAGGING, ON PURPOSE, TWO WAYS:
#   :latest          the demo workloads (app/k8s hero deployments) keep the mutable tag.
#                    That IS the anti-pattern being taught - Defender findings and the
#                    gate verdict are per digest, so the same manifest can flip from
#                    allowed to denied without anyone editing it.
#   :<sha>-<stamp>   an immutable tag pushed alongside, so a talk can be replayed against
#                    exactly the image that was demoed.
# The CONTROL PANEL is different: it is lab infrastructure, not demo content, so it is
# deployed BY DIGEST. Updating a Container App to an unchanged ':latest' string can create
# a revision that keeps running the previous image - a real trap that costs ten confusing
# minutes on stage.
#
# BUILD_PHASE lets deploy.sh overlap the slow parts:
#   all     (default) build + push, then point the Container App at the new digest
#   images  build + push only; runs while the infrastructure is still deploying
#   panel   point the Container App at the digest pushed under BUILD_TAG (same tag as images)
set -euo pipefail

# needs the `containerapp` CLI extension; `make deploy` installs it (scripts/az-prereqs.sh).
# run standalone on a fresh machine, let az fetch it instead of prompting.
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true
ACR_NAME="${ACR_NAME:?set ACR_NAME (e.g. defdemoacrxxxxxx)}"
RG="${RG:-rg-defdemo}"
APP_NAME="${APP_NAME:-defdemo-app}"
BUILD_PHASE="${BUILD_PHASE:-all}"
PANEL_REPO="${PANEL_REPO:-aca-webapp}"  # the image the control panel (Container App) runs; aks-webapp is what Flux deploys

LOGIN_SERVER="$(az acr show -n "$ACR_NAME" --query loginServer -o tsv)"
az acr login --name "$ACR_NAME"

# Immutable tag: the commit that produced the image, plus a stamp so repeated builds from a
# dirty tree stay distinguishable.
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
BUILD_TAG="${BUILD_TAG:-${GIT_SHA}-$(date -u +%Y%m%d%H%M%S)}"

digest_of() {   # repo:tag -> sha256:...  (read back from the registry, not from the daemon)
  az acr repository show-manifests -n "$ACR_NAME" --repository "$1" \
    --query "[?contains(tags, '$2')].digest | [0]" -o tsv 2>/dev/null
}

# ONE PLATFORM, NO ATTESTATIONS. BuildKit (the default builder since Docker 23) attaches a
# provenance attestation, which turns even a single-platform push into an OCI image INDEX:
# one linux/amd64 manifest plus an "unknown/unknown" attestation manifest. Defender's
# registry scan and the gated-deployment artifact check do not resolve that index yet, so
# the digest the cluster pulls ends up with no findings and the gate verdict is wrong.
# Build exactly one linux/amd64 image manifest instead. AKS nodes are amd64.
BUILD_FLAGS=(--platform linux/amd64 --provenance=false --sbom=false)

PANEL_DIGEST=""
if [[ "$BUILD_PHASE" != "panel" ]]; then
  # Two build contexts: aca-webapp (app/webapp) is the Container Apps control panel,
  # aks-webapp (app/aks-webapp) is the small public storage dashboard Flux deploys to the
  # cluster. Both carry the planted vulnerable content, so both trip the image gate.
  for REPO in aca-webapp aks-webapp; do
    IMG="$LOGIN_SERVER/$REPO"
    CTX="app/webapp"; [[ "$REPO" == "aks-webapp" ]] && CTX="app/aks-webapp"
    docker build "${BUILD_FLAGS[@]}" -t "$IMG:latest" -t "$IMG:$BUILD_TAG" "$CTX"
    docker push "$IMG:latest"
    docker push "$IMG:$BUILD_TAG"
    echo "pushed $IMG:latest and :$BUILD_TAG"
    if [[ "$REPO" == "$PANEL_REPO" ]]; then
      PANEL_DIGEST="$(digest_of "$REPO" "$BUILD_TAG")"
    fi
  done

  # The Defender alert-simulation image the control panel runs as a Job.
  SIM="$LOGIN_SERVER/mdc-alert-triage"
  docker build "${BUILD_FLAGS[@]}" -t "$SIM:latest" -t "$SIM:$BUILD_TAG" app/mdc-alert-simulation
  docker push "$SIM:latest"
  docker push "$SIM:$BUILD_TAG"
  echo "pushed $SIM:latest and :$BUILD_TAG"
fi

if [[ "$BUILD_PHASE" == "images" ]]; then
  echo ">> Images pushed under $BUILD_TAG; the Container App is updated in the panel phase."
  exit 0
fi
[[ -n "$PANEL_DIGEST" ]] || PANEL_DIGEST="$(digest_of "$PANEL_REPO" "$BUILD_TAG")"

if [[ -n "$PANEL_DIGEST" ]]; then
  echo ">> Pointing the control panel at ${PANEL_REPO}@${PANEL_DIGEST}"
  az containerapp ingress update -n "$APP_NAME" -g "$RG" --target-port 8080 >/dev/null
  az containerapp update -n "$APP_NAME" -g "$RG" \
    --image "$LOGIN_SERVER/${PANEL_REPO}@${PANEL_DIGEST}" >/dev/null
else
  echo "!! Could not read the digest back from ACR; falling back to the mutable tag."
  echo "   A revision created this way can keep serving the PREVIOUS image."
  az containerapp ingress update -n "$APP_NAME" -g "$RG" --target-port 8080 >/dev/null
  az containerapp update -n "$APP_NAME" -g "$RG" \
    --image "$LOGIN_SERVER/${PANEL_REPO}:latest" >/dev/null
fi

echo ""
echo ">> Immutable tag for this build: $BUILD_TAG"
echo ">> Demo workloads still reference :latest on purpose (app/k8s)."
echo ">> Done. The ACR scan + Defender findings appear within minutes to hours."
