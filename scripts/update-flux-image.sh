#!/usr/bin/env bash
# Update the app image in one Flux-managed deployment manifest.
set -euo pipefail

MANIFEST="${1:?usage: update-flux-image.sh <manifest> <registry/repository:tag>}"
IMAGE_REF="${2:?usage: update-flux-image.sh <manifest> <registry/repository:tag>}"

if [[ ! "$IMAGE_REF" =~ ^[a-z0-9.-]+/(aks-webapp|workflow-scanned-webapp):[A-Za-z0-9_.-]+$ ]]; then
  echo "Invalid demo image reference: $IMAGE_REF" >&2
  exit 2
fi

PATTERN='^[[:space:]]*image:[[:space:]]*(\$\{ACR_LOGIN_SERVER\}/|[[:alnum:].-]+/)?(aks-webapp|workflow-scanned-webapp):[^[:space:]]+'
MATCHES="$(grep -Ec "$PATTERN" "$MANIFEST" || true)"
if [[ "$MATCHES" != 1 ]]; then
  echo "Expected exactly one Flux app image in $MANIFEST; found $MATCHES" >&2
  exit 1
fi

sed -E -i \
  's#^([[:space:]]*image:[[:space:]]*)(\$\{ACR_LOGIN_SERVER\}/|[[:alnum:].-]+/)?(aks-webapp|workflow-scanned-webapp):[^[:space:]]+#\1'"$IMAGE_REF"'#' \
  "$MANIFEST"
