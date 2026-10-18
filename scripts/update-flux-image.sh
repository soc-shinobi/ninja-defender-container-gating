#!/usr/bin/env bash
# Update the app image in one Flux-managed deployment manifest.
set -euo pipefail

MANIFEST="${1:?usage: update-flux-image.sh <manifest> <registry/repository:tag>}"
IMAGE_REF="${2:?usage: update-flux-image.sh <manifest> <registry/repository:tag>}"

# A tag (repo:tag) or a digest (repo@sha256:...): the security-gated workflow deploys by digest.
if [[ ! "$IMAGE_REF" =~ ^[a-z0-9.-]+/(aks-webapp|misconfig-alpine)(:[A-Za-z0-9_.-]+|@sha256:[0-9a-f]{64})$ ]]; then
  echo "Invalid demo image reference: $IMAGE_REF" >&2
  exit 2
fi

# workflow-scanned-webapp is gone (the security-gated workflow pushes aks-webapp now); it is
# still matched here only so a manifest that holds it can be switched over.
PATTERN='^[[:space:]]*image:[[:space:]]*(\$\{ACR_LOGIN_SERVER\}/|[[:alnum:].-]+/)?(aks-webapp|workflow-scanned-webapp|misconfig-alpine)[:@][^[:space:]]+'
MATCHES="$(grep -Ec "$PATTERN" "$MANIFEST" || true)"
if [[ "$MATCHES" != 1 ]]; then
  echo "Expected exactly one Flux app image in $MANIFEST; found $MATCHES" >&2
  exit 1
fi

sed -E -i \
  's#^([[:space:]]*image:[[:space:]]*)(\$\{ACR_LOGIN_SERVER\}/|[[:alnum:].-]+/)?(aks-webapp|workflow-scanned-webapp|misconfig-alpine)[:@][^[:space:]]+#\1'"$IMAGE_REF"'#' \
  "$MANIFEST"
