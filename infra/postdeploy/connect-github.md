# Runbook: connect GitHub to Defender for Cloud

This step has no clean IaC path (OAuth consent flow), so it is a tracked manual
runbook. Do it once, then it is stable. Verified against Microsoft Learn 2026-09-18.

## Prerequisites

- Defender CSPM enabled on the subscription (the Bicep does this).
- Two GitHub repos that both build `app/webapp`: Team Atlas and Team Ship-It.
- You are a GitHub org owner (needed for the connector and push protection).

## What connecting actually does (and why it is the whole thesis)

Connecting the code environment is not just "add a data source". Per Microsoft
(https://learn.microsoft.com/en-us/azure/defender-for-cloud/container-image-mapping,
*Option 1: Connect your code environment to Defender for Cloud*):

> When you connect an Azure DevOps or GitHub environment to Defender for Cloud, a set of
> automated tools is triggered automatically. The automated tools do **not** affect your
> existing DevOps workflows and enable code-to-runtime mapping.

Read that twice on stage. It is the talk in one sentence from Microsoft's own docs: the
connector turns on code-to-runtime mapping for **every** repo in the org **without touching a
single pipeline**. Team Ship-It never edits a workflow and their images still map back to
their commits. That is Option 1 of three mapping methods; the Atlas pipeline also stamps OCI
labels (Option 2) so mapping survives even without a connector.

Two caveats that matter for a demo:

- **Supported for Azure DevOps and GitHub** only.
- **Images built and deployed *before* you connect may have limited mapping support.** So
  connect the org **before** you build and deploy the hero image, not after. This is why the
  connector is step one of the pre-seeding, several days ahead.

## 1. Create the connector

1. Azure portal > Microsoft Defender for Cloud > Environment settings.
2. **Add environment > GitHub**.
3. Authorize the Defender for Cloud "DevOps security" GitHub app for your organization.
4. Select the organization and the two repos.

## 2. Turn on agentless code scanning (Preview)

1. On the GitHub connector > **Settings**.
2. Enable **Agentless code scanning**. It scans the default branch daily, builds
   an SBOM, finds code / IaC / dependency / secret issues. It cannot break builds.
3. Seed it **3 days before** a talk so findings exist to show live.

## 3. Turn on push protection + branch protection (GitHub side)

In each repo (or at org level):
- Settings > Code security > **Push protection** ON.
- Settings > Branches > protect `main`: require a PR + 1 review.

## 4. (Optional) Pull request annotations

Needs GitHub Advanced Security. Defender for Cloud > DevOps security >
Manage resources > toggle **Pull request annotations** on.

## 5. Wire the Defender CLI auth in Atlas's pipeline

Preferred: connector-based auth (no token in the pipeline) once the connector
above exists. Fallback: token-based auth via
Environment settings > Integrations > Add integration > DevOps Ingestion,
then set `DEFENDER_CLIENT_ID/SECRET/TENANT_ID` as repo secrets.
See `.github/workflows-samples/atlas-ci.yml`.

Reference: https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-cli-overview
