#!/usr/bin/env bash
# Layer 0 beat: plant a FAKE secret so the gitleaks pre-commit hook blocks the next commit.
#
# WHY A SCRIPT AND NOT A COMMITTED FILE: the hook scans STAGED CHANGES only. A secret that is
# already in the repo's history triggers nothing, so the file has to be newly added at demo
# time. That is also why this file is never committed - it would neuter the beat and would
# ship a credential-shaped string to whoever clones the lab.
set -euo pipefail

TARGET="app/aks-webapp/config/demo.env"
c() { printf '\033[%sm%s\033[0m\n' "$1" "$2"; }

if [[ ! -d .git ]]; then
  echo "Run this from the repo root." >&2
  exit 1
fi

mkdir -p "$(dirname "$TARGET")"
cat > "$TARGET" <<'SECRET'
# DEMO ONLY - planted on purpose for the Layer 0 beat. Every value here is FAKE.
APP_ENV=production
APP_DEBUG=false

# Fake AWS credentials. Shaped like the real thing so the scanner fires; not real keys.
AWS_ACCESS_KEY_ID=AKIAZZ4DEMO7LAB9QRST
AWS_SECRET_ACCESS_KEY=Kd8fQ2vN1xPzR7bLmY4tW6hJ3sA5cE0gU9iO2pXn

# Fake connection string.
DATABASE_URL=postgres://appuser:Sup3rS3cr3t-D3mo-Pw@db.internal.lab:5432/atlas
SECRET

c '1;32' "✔ planted $TARGET (fake credentials)"
echo ""

if [[ ! -f .git/hooks/pre-commit ]]; then
  c '1;33' "⚠ No pre-commit hook installed in this clone - the commit will NOT be blocked."
  c '1;33' "  Run 'make hooks' first, or use this as the 'developer never installed it' beat."
  echo ""
fi

if git check-ignore -q "$TARGET"; then
  c '1;31' "✖ $TARGET is gitignored, so it cannot be staged and the beat cannot run."
  exit 1
fi

c '1;36' "Now run:"
echo "  git add $TARGET"
echo "  git commit -m 'add app config'              # blocked by gitleaks"
echo "  git commit -m 'add app config' --no-verify  # goes through - that is the point"
echo ""
c '0;90' "Clean up with: rm $TARGET"
