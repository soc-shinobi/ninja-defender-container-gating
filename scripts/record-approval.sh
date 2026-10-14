#!/usr/bin/env bash
# Summarise the showcase approval of this run honestly: who approved it, or that nothing was
# enforced. Runs as the only step of the `approval` jobs that use `environment: showcase`.
#
# Required reviewers on an environment are what make GitHub pause the job. GitHub offers them
# on private repositories only with Enterprise, so on this private personal repo `showcase` has
# no protection rules and the job passes at once. After the repo goes public, run
# scripts/setup-approval-gate.sh (make approval-gate) and the same job waits for a reviewer;
# no workflow change needed.
#
# Needs: GH_TOKEN (actions: read), GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_STEP_SUMMARY.
# Optional: ACTION (default "deployment"), REPO_PRIVATE ("true"/"false"), ENV_NAME.
set -euo pipefail

ENV_NAME="${ENV_NAME:-showcase}"
ACTION="${ACTION:-deployment}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

RULES="$(gh api "repos/$GITHUB_REPOSITORY/environments/$ENV_NAME" \
  --jq '[.protection_rules[]?.type] | join(",")' 2>/dev/null || true)"
APPROVERS="$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/approvals" \
  --jq '[.[] | select(.state == "approved") | .user.login] | unique | join(", ")' 2>/dev/null || true)"

if [[ -n "$APPROVERS" ]]; then
  echo "### ✅ Showcase $ACTION approved by $APPROVERS" >> "$SUMMARY"
elif [[ "$RULES" == *required_reviewers* ]]; then
  # Reviewers are configured, so GitHub held the job until one approved; only the name is missing.
  echo "### ✅ Showcase $ACTION approved (required reviewers on \`$ENV_NAME\`)" >> "$SUMMARY"
else
  if [[ "${REPO_PRIVATE:-}" == "true" ]]; then
    WHY="private repository: required reviewers need a public repo or GitHub Enterprise"
  else
    WHY="no required reviewers on \`$ENV_NAME\` yet: run \`make approval-gate\`"
  fi
  echo "::notice title=Approval not enforced::$ENV_NAME has no required reviewers ($WHY)"
  {
    echo "### ⚪ Showcase approval not enforced"
    echo ""
    echo "The \`$ENV_NAME\` environment has no required reviewers, so this $ACTION continued without a review ($WHY)."
  } >> "$SUMMARY"
fi
