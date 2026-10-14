#!/usr/bin/env bash
# Turn the `showcase` environment into a real approval gate: required reviewers, main only.
# Run once after the repository is public (GitHub offers required reviewers on private repos
# only with Enterprise). Idempotent: re-running just rewrites the same rules.
#
#   APPROVERS            comma-separated GitHub logins (default: the logged-in gh user)
#   PREVENT_SELF_REVIEW  true = whoever starts the run cannot approve it (default false, so a
#                        solo presenter can approve their own demo run)
#   ENV_NAME             default showcase
#
# Needs: gh logged in as a repo admin.
set -euo pipefail

ENV_NAME="${ENV_NAME:-showcase}"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
VISIBILITY="$(gh repo view --json visibility -q .visibility)"

if [[ "$VISIBILITY" != "PUBLIC" ]]; then
  echo "$REPO is ${VISIBILITY,,}. Required reviewers need a public repository (or GitHub Enterprise)." >&2
  echo "Until then the approval jobs pass without a review and say so in the run summary." >&2
  exit 1
fi

APPROVERS="${APPROVERS:-$(gh api user -q .login)}"
REVIEWERS="$(for login in ${APPROVERS//,/ }; do
  gh api "users/$login" --jq '{type: "User", id: .id}'
done | jq -s .)"

jq -n --argjson reviewers "$REVIEWERS" --argjson psr "${PREVENT_SELF_REVIEW:-false}" '{
  reviewers: $reviewers,
  prevent_self_review: $psr,
  wait_timer: 0,
  deployment_branch_policy: {protected_branches: false, custom_branch_policies: true}
}' | gh api -X PUT "repos/$REPO/environments/$ENV_NAME" --input - > /dev/null

# custom_branch_policies needs the allowed branch itself; ignore "already exists" on re-runs.
gh api -X POST "repos/$REPO/environments/$ENV_NAME/deployment-branch-policies" \
  -f name=main -f type=branch > /dev/null 2>&1 || true

echo "$ENV_NAME on $REPO now requires approval from: $APPROVERS (deployments from main only)."
gh api "repos/$REPO/environments/$ENV_NAME" \
  --jq '.protection_rules[] | "  rule: \(.type)\(if .reviewers then " -> " + ([.reviewers[].reviewer.login] | join(", ")) else "" end)"'
