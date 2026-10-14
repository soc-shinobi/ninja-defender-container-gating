# Plan: an approval gate for CVE exception requests

A blocked team asks for an exception in GitHub, a Logic App takes the request to cloud
security in Teams, security approves or rejects, and the decision is written back as
annotations that the SOC can read later. **The playbook decides. It does not configure.**
Verified against Microsoft Learn and a live tenant on 2026-09-19.

## Scope, and what is deliberately left manual

| Layer | Decision |
| --- | --- |
| **Gated-deployment rule** (Defender > Environment settings > Security rules > Gated deployment > Vulnerability assessment - the `CloudNativeCompute` policy blade) | **Stays manual and pre-coordinated with the cluster-owner team.** No documented public API exists: `az provider operation show --namespace Microsoft.Security` lists only `alertsSuppressionRules`, `governanceRules`, `standardAssignments` and `securityStandards`, and Learn documents this blade as portal-only. See "Future" below. |
| **Approval** | Automated. GitHub raises it, a Logic App carries it to Teams, security decides, the decision is recorded. |
| **Annotations on the workload** | Automated on approval, because this is what the SOC reads at 02:00. |

So the honest promise to a dev team: *your request reaches security in minutes, the decision
is recorded with an owner and an expiry, and the workload carries that context from then on.*
Not: *your deployment turns green automatically.* Someone still adds the allowed-CVE entry to
the rule, on purpose, with the cluster owners in the loop.

## Who runs this, and who does not

| | Platform / cluster team | Application team | Cloud security |
| --- | --- | --- | --- |
| Triggers the request | no | **yes** - their release is blocked, they own the image and the fix | no |
| Approves | no | no | **yes** - they own the risk |
| Gets notified | in aggregate only | every time | every request |
| Acts on the outcome | only if the rule scope or a tier changes | rebuild, or carry the annotation | grants the time-bound exemption |

The cluster team is deliberately **not** in the loop for a normal CVE exception. They did not
build the image, they cannot fix it, and routing every denial past them turns the platform
team into a ticket queue - which is how gates get switched off.

Three cases where they do belong in the conversation:

1. **Wrong placement.** The real answer is a different tier, not an exemption. That is a
   platform decision about exposure, not a security decision about a CVE.
2. **The request would change the rule's scope** - exempting a namespace rather than an
   image. That is policy, and policy is written by platform and security together.
3. **The platform team owns the base image.** Then "no fix available" for the app team means
   "bump the golden image" for the platform team, and the request is really a platform
   backlog item wearing an exception costume. Watch for the same CVE arriving from several
   teams: that is the tell.

## Flow

```
developer                GitHub                    Logic App                Teams             Azure
    |  exception request    |                          |                      |                 |
    |---------------------->|  issue form / PR         |                      |                 |
    |                       |  workflow validates      |                      |                 |
    |                       |  owner approves (gate 1) |                      |                 |
    |                       |------ webhook ---------->|  re-verify from ARG  |                 |
    |                       |                          |--------------------->| adaptive card   |
    |                       |                          |                      |  (gate 2)       |
    |                       |<----- decision comment --|<---------------------|                 |
    |                       |  annotation PR opened    |                      |                 |
    |                       |                          |--- record decision ->|                 |
```

Two gates, two different accountabilities. **Gate 1 in GitHub** is the owning team saying
"we want this and we stand behind the justification". **Gate 2 in Teams** is cloud security
accepting the risk. Neither replaces the other, and neither is a rubber stamp for the other.

## 1. GitHub: raise and validate the request

1. **Issue form** (`.github/ISSUE_TEMPLATE/cve-exception.yml`) with typed fields: image
   **digest** (not tag), workload, namespace, CVE list, branch from the denial runbook (B-E),
   justification, compensating controls, requested expiry.
2. **Validation workflow** rejects nonsense before a human sees it:
   - the digest exists in the registry
   - the CVEs are actually reported against *that digest* - query Resource Graph rather than
     trusting the form, so typos and wishful CVE lists bounce automatically
   - a fix is not already available (if it is, the workflow closes the request and points at
     branch B: bump it, that is faster than this process)
   - the requested expiry is within policy
3. **Gate 1**: a GitHub Environment with required reviewers (the owning team's leads), or
   CODEOWNERS on the acceptance path. Cheap, native, auditable.

## 2. The trigger

GitHub calls the Logic App. The default below is the public HTTP trigger; see "Getting the
trigger off the internet" for the private-endpoint variant, which is the better end state.

GitHub calls the Logic App HTTP trigger. A Logic App Consumption trigger URL is public and
protected only by the SAS `sig` in the query string, so treat it as a public endpoint:

- **Re-verify everything server-side.** The card that security sees is built from Azure
  (Resource Graph findings for that digest, the workload's tier, the rule that denied it),
  never from the webhook body. The body supplies identifiers; Azure supplies facts. Without
  this, whoever finds the URL can put a convincing lie in front of your approvers.
- **Authenticate the caller**: a shared secret header, or an HMAC of the body that the
  workflow computes from a GitHub secret and the Logic App recomputes. Reject mismatches
  silently.
- **Constrain the source**: restrict the trigger to GitHub's published Actions IP ranges
  (`https://api.github.com/meta`).
- **Rotate** the SAS key on a schedule, and treat the URL as a secret in GitHub.
- **Deduplicate** on `(digest, CVE set, namespace)` and rate-limit, so a retry loop or a
  replayed request cannot spam the approvers.
- Better, when it is available to you: front the workflow with APIM or a Function using
  GitHub OIDC, and drop the shared secret entirely. The webhook is the pragmatic start,
  not the end state.

### Authenticating the trigger: three options, one target

The Logic App stays the orchestrator in all of them - it owns the human-in-the-loop approval,
the Teams and GitHub connectors, and the ARM reads. What changes is only **how the caller
proves who it is**.

| Option | Caller proves identity by | Exposure | Cost / operations |
| --- | --- | --- | --- |
| **A. Public HTTP trigger + HMAC** | shared secret or body HMAC, plus GitHub Actions IP ranges | internet-reachable | lowest, nothing to run. **What this lab does.** |
| **B. Self-hosted runner -> private endpoint** | network reachability, plus Entra on the workflow | no public surface | Logic App **Standard**, runner infrastructure, private DNS. A machine you now defend. |
| **C. APIM (or Function) front door + GitHub OIDC** | a **federated Entra token**, no secret anywhere | public, but nothing gets through unauthenticated | APIM tier cost, no runner to operate. **The target.** |

#### C, in detail - front door authenticates, Logic App orchestrates

1. The GitHub workflow requests an OIDC `id-token` (`permissions: id-token: write`). No
   secret is stored in GitHub, so there is nothing to leak or rotate.
2. A **federated identity credential** on an app registration trusts
   `https://token.actions.githubusercontent.com` for a **specific repository, branch and
   environment** - the subject claim is the authorisation decision.
3. **APIM** validates the token with a `validate-jwt` policy: issuer, audience, and the
   `repository` / `environment` claims. A token from another repo, or from a branch that is
   not the protected one, is rejected at the edge and never reaches the workflow.
4. APIM also does what a webhook cannot: `validate-content` against the request schema, rate
   limiting and quotas per repository, and one place where every call is logged.
5. APIM calls the Logic App. The workflow is then locked to APIM only - IP restriction for
   Consumption, or VNet/private endpoint for Standard.
6. The Logic App does the part it is good at: **Teams Adaptive Card approval (HITL)**, the
   GitHub connector for the write-back, ARM for the re-verification, and the run history for
   the audit trail.

Why this beats both others: A's shared secret is a credential that leaks and grants anyone
who holds it an approval request; B removes internet exposure but adds a runner that holds
credentials, executes repository code and must be patched. C has **no standing credential
and no extra machine**, and it authorises on claims - "this repo, this environment" - which
is a stronger statement than "someone who knows the URL" or "someone inside the VNet".

Tier notes: APIM Consumption supports `validate-jwt` and bills per call, which suits a
workflow that fires a few times a week; VNet integration and private endpoints need the
higher tiers. A Function with Easy Auth validating the same token is the cheaper variant, at
the price of code you maintain.

**B and C compose.** The strongest version is C's claim-based authentication in front of a
Logic App Standard that is itself on a private endpoint. Start with C: it removes the secret,
which is the weakest part of A, without adding infrastructure to defend.

## 3. Teams: the decision, and only the decision

Adaptive Card to the cloud-security channel showing the re-verified facts: workload, tier,
digest, CVEs with severity and fix status, exploitability, the team's justification and
compensating controls, the requested expiry, and the denial history (how many times, since
when).

Actions: **Approve**, **Reject**, **Needs discussion**. Approval captures approver, timestamp
and expiry date. That is the whole action - the playbook writes no Azure configuration.

Guardrails rendered into the card rather than kept in a wiki: a fix being available is
called out as "this should be branch B"; edge tier asks for a second approver; an expiry
beyond policy cannot be selected.

## 4. Write the context back

This is the part that pays off months later, when an analyst meets the workload during an
incident.

1. **Comment on the GitHub issue/PR** with the decision, the approver and the expiry.
2. **Open a PR adding the `risk.acceptance/*` annotations** to the workload manifest -
   generated from the approved request, so the CVE list and expiry cannot drift from what was
   actually approved. Fields as in `app/k8s/x-mdc-allowed/deployment.yaml`:
   `cves`, `justification`, `approved-by`, `approved-at`, `expires`, `ticket`,
   `compensating-control`, and `defender-exemption` left empty until someone adds the rule
   entry by hand.
3. **Record the decision** where security reports from - a ticket, a table, a workbook.
   The Logic App run history is not a record.
4. On **reject**, comment with the reason and the runbook branch. Silent rejection is how
   teams learn to route around the process.

## 5. Expiry

The approval carries a date and nothing enforces it automatically, so the watchdog matters
more here than in a fully automated design: a daily job lists workloads whose
`risk.acceptance/expires` has passed and reopens the request. The control panel's
"accepted risk" command group shows the same view from inside the cluster.

## Future: when the rule gets an API

If the gated-deployment rule and its allowed-CVE list become API-manageable, step 3 gains one
action - on approve, write the allowed CVE with the approved `Valid until` - and step 4's
`defender-exemption` annotation gets filled in automatically. Nothing else in the design
changes, which is why the decision and the configuration are kept separate from the start.

The neighbouring API that *does* exist today, for reference:
`PUT {resourceId}/providers/Microsoft.Security/standardAssignments/{guid}?api-version=2024-08-01`
with `effect: "Exempt"`, `exemptionData.assignedAssessment.assessmentKey`,
`exemptionCategory: waiver|mitigated` and `expiresOn`. That exempts the **finding**
(recommendation state, secure score) - it does not change an admission decision, so it is not
part of this flow.

## Build order

| Step | Value on its own |
| --- | --- |
| 1. Issue form + validation workflow | bad requests never reach a human |
| 2. Gate 1 in GitHub | the owning team owns its own ask |
| 3. Logic App: webhook in, re-verify, Teams card, decision out | security decides in minutes, in writing |
| 4. Annotation PR on approve | the SOC gets context without asking anyone |
| 5. Expiry watchdog | accepted risk stops being permanent |
