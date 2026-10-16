#!/usr/bin/env bash
# Switch the misconfiguration demo pod between a privileged root container and a restricted one.
# Rewrites only the marked securityContext block in app/k8s/x-mdc-misconfig/privileged-root.yaml.
#   bash scripts/set-misconfig-mode.sh privileged
#   bash scripts/set-misconfig-mode.sh restricted
set -euo pipefail

MODE="${1:?usage: set-misconfig-mode.sh privileged|restricted}"
MANIFEST="${MISCONFIG_MANIFEST:-app/k8s/x-mdc-misconfig/privileged-root.yaml}"

case "$MODE" in
  privileged)
    BLOCK='          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true' ;;
  restricted)
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

BLOCK="$BLOCK" python3 - "$MANIFEST" <<'PY'
import os, re, sys
path = sys.argv[1]
text = open(path).read()
pattern = re.compile(r"(# >>> securityContext[^\n]*\n).*?(\n[ \t]*# <<< securityContext)", re.S)
if len(pattern.findall(text)) != 1:
    sys.exit(f"expected exactly one marked securityContext block in {path}")
open(path, "w").write(pattern.sub(lambda m: m.group(1) + os.environ["BLOCK"] + m.group(2), text))
PY
echo "$MANIFEST: securityContext set to $MODE"
