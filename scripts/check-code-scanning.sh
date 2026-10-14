#!/usr/bin/env bash
# Detect whether this repository can accept SARIF uploads through GitHub code scanning.
# Public repositories can use code scanning directly. Private repositories need GitHub
# Code Security (formerly Advanced Security) enabled for the repository.
set -uo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY is required}"

enabled=false
visibility="${REPOSITORY_VISIBILITY:-unknown}"

if [[ "$visibility" == "public" ]]; then
  enabled=true
elif gh api "repos/$GITHUB_REPOSITORY/code-scanning/alerts?per_page=1" \
  --silent >/dev/null 2>&1; then
  # A successful response proves that code scanning is enabled and this workflow's
  # token can access it. This avoids relying on repository security settings, which
  # GitHub can hide from tokens without repository-administration permission.
  enabled=true
fi

echo "enabled=$enabled" >> "$GITHUB_OUTPUT"

if [[ "$enabled" != "true" ]]; then
  {
    echo "### ⚪ GitHub code scanning upload skipped"
    echo
    if [[ "$visibility" == "private" ]]; then
      echo "This repository is private and GitHub Code Security/Advanced Security is not enabled or licensed."
    else
      echo "GitHub code scanning availability could not be confirmed for this repository."
    fi
    echo "The scan itself still ran; its SARIF results remain available as a workflow artifact."
  } >> "$GITHUB_STEP_SUMMARY"
fi
