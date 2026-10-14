#!/usr/bin/env bash
# Post-deploy: create and PUBLISH a Foundry agent for chat mode B.
# Threat detection only covers PUBLISHED Foundry agents, and agent-level
# security needs a Microsoft Agent 365 license (since 2026-07-01).
# Mode A (direct model inference) is already covered by Defender for AI Services
# and needs none of this.
#
# This is a template: the agent create/publish path uses the Foundry SDK or
# `azd ai`. Fill in with your project endpoint from the deployment outputs.
set -euo pipefail
echo "Foundry endpoint: ${FOUNDRY_ENDPOINT:-<from deployment outputs>}"
cat <<'EOF'
Steps (SDK / azd ai):
  1. Create a prompt agent on the project, same system prompt as the app.
  2. Publish it (unpublished/playground agents are NOT covered by threat detection).
  3. Grant the Container App identity the "Foundry Agent Consumer" role on the agent.
  4. Point chat mode B at the published agent endpoint.
  5. Ensure the tenant has an Agent 365-eligible license for agent-level detection.

Open verification (test in your tenant): does a jailbreak sent THROUGH the agent
still raise the model-layer Prompt Shields alert from Defender for AI Services?
If yes, mode B keeps a partial safety net even without Agent 365.
EOF
