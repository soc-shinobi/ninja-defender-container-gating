#!/usr/bin/env bash
# Switch the misconfiguration demo pod between a privileged root container and a restricted one.
# Rewrites the marked securityContext block in app/k8s/x-mdc-misconfig/privileged-root.yaml and
# names the Deployment after the mode (privileged-root | restricted), so the pod name says which.
#   bash scripts/set-misconfig-mode.sh privileged
#   bash scripts/set-misconfig-mode.sh restricted
set -euo pipefail

MODE="${1:?usage: set-misconfig-mode.sh privileged|restricted}"
MANIFEST="${MISCONFIG_MANIFEST:-app/k8s/x-mdc-misconfig/privileged-root.yaml}"

case "$MODE" in
  privileged)
    NAME=privileged-root
    BLOCK='          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true' ;;
  restricted)
    NAME=restricted
    BLOCK='          securityContext:
            privileged: false
            runAsNonRoot: true
            runAsUser: 1000
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault' ;;
  *) echo "mode must be privileged or restricted (got: $MODE)" >&2; exit 2 ;;
esac

BLOCK="$BLOCK" NAME="$NAME" python3 - "$MANIFEST" <<'PY'
import os, re, sys
path = sys.argv[1]
text = open(path).read()
pattern = re.compile(r"(# >>> securityContext[^\n]*\n).*?(\n[ \t]*# <<< securityContext)", re.S)
if len(pattern.findall(text)) != 1:
    sys.exit(f"expected exactly one marked securityContext block in {path}")
text = pattern.sub(lambda m: m.group(1) + os.environ["BLOCK"] + m.group(2), text)
# Deployment name, its labels and selector: a new name is a new Deployment, and Flux prunes the old.
text = re.sub(r"(\bname: |\bapp: )(?:privileged-root|restricted)\b", lambda m: m.group(1) + os.environ["NAME"], text)
open(path, "w").write(text)
PY
echo "$MANIFEST: securityContext set to $MODE, Deployment $NAME"
