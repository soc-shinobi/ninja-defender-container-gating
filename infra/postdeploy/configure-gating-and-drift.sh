#!/usr/bin/env bash
# Post-deploy: create the gated deployment rule and the binary drift policy.
# These have no ARM/Bicep resource type today, so they are configured via the
# Defender for Cloud REST API. Verified against Microsoft Learn 2026-09-18.
#
# Prereqs: Defender for Containers on, sensor + Security Gating installed on the
# AKS cluster (done by the Bicep securityProfile), Registry access + Security
# findings on. Wait until the cluster's first image scan has produced a signed
# findings artifact before you expect DENY to behave predictably.
set -euo pipefail

SUB_ID="$(az account show --query id -o tsv)"
API="2024-01-01"   # adjust if the security rules API version has moved

echo ">> This script is a template. The gated-deployment and drift-policy REST"
echo "   surfaces are still stabilising; confirm the current API path in the"
echo "   portal (Environment settings > Security policies) before automating."
echo ""
echo "Portal path for the DEMO rule (recommended for the talk):"
cat <<'EOF'
  Defender for Cloud > Environment settings > <subscription>
    > Defender plans > Containers > Settings
      - Confirm: Defender sensor (Security Gating ON), Registry access (Security findings ON)
    > Security policies / Vulnerability assessment > Add rule

      Rule  x-mdc-blocked-deny
        Action:    Deny
        Scope:     cluster = <defdemo-aks>, namespace = x-mdc-blocked
        Condition: severity >= High
        Unscanned images: Deny
      Deliberately OUT OF SCOPE: x-mdc-allowed. Flux deploys the identical digest there
        and exposes it through a LoadBalancer to demonstrate namespace-scoped enforcement.
      Exclusions: system namespaces kube-system, flux-system, mdc, demo-ops
      Break-glass: resource / CVE exemptions WITH AN EXPIRY DATE - never disable the rule.

  Binary drift policy:
    Environment settings > Containers drift policy > Add rule
      Name:      drift-alert-demo-ns
      Action:    Drift detection alert   (flip to "Drift detection blocking" live)
      Scope:     namespace = x-mdc-blocked
      Allow list: (leave empty so any external process alerts)

    Add rule   (the isolation drill: drift -> isolate pod -> heartbeat fails)
      Name:      drift-alert-allowed-ns
      Action:    Drift detection alert   (alert only - the pod must keep running so you
                 can isolate it from Defender XDR and watch its heartbeat fail)
      Scope:     namespace = x-mdc-allowed
      Allow list: (leave empty)
      Trigger:   control panel > command library > "binary drift + isolation"
EOF

echo ""
echo ">> Subscription: $SUB_ID   (API hint: $API)"
echo ">> When the REST path is confirmed, wire 'az rest --method put --url ...' here."
