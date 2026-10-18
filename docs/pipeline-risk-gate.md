# The pipeline risk gate: fixable means block, otherwise decide by exposure

This is how the CVE decision model (`docs/cve-decision-model.md`) is applied **inside the
pipeline**, at build time, before an image is pushed. Design, verified sources, and the
honest limits. Status: design, 2026-09-18. Implementation is the `risk-gate` job in
`atlas-ci`.

## The two-part rule, and why it splits cleanly

| Question | Property of | Known at build time? | Source |
| --- | --- | --- | --- |
| Is a patch available? | the **finding** | yes | the scan output (fix status / fixed version per CVE) |
| Is it exposed, what is the blast radius? | the **runtime** | not for this image, but yes for the **previous** version of the same workload | the Defender security graph, via code-to-runtime mapping |

That second row is the trick. The image being built has never run, but this repo's last image
is running right now, and Defender already maps repo to image to running workload. The
exposure of the previous version is the best available predictor of the next one. The
pipeline asks the graph: *"for workloads built from this repo, what are the risk factors?"*

## Inputs the gate collects

1. **Scan findings**: the Defender CLI SARIF (or trivy / grype SARIF when the dropdown is used).
   Per CVE: severity, **fix available** (fixed version present), exploitability where the
   scanner provides it. Adapters per scanner, because the field names differ.
2. **Exposure**, checked in three layers that stack from cheapest to richest. See the next
   section, *How exposure is checked*, for the exact mechanics and the verified query shapes.
3. **Declared enrichment (intent)**: `security/exposure.yaml`, only for what manifests cannot
   express, such as data classification and the workload identity's reach:
   ```yaml
   data: user-pii        # none | internal | user-pii | regulated
   identity_reach: none  # none | cluster | subscription
   owner: team-shipit
   ```
4. **Decisions on record**: active Defender **exemptions** (`Microsoft.Security/standardAssignments`)
   matching the CVE for this scope, not expired. A Mitigated or Non-patchable exemption that
   security recorded in Defender is honored by the pipeline automatically. No per-team config,
   which is the whole point: the record lives centrally, every pipeline reads it.

**Reality beats intent.** If the graph says the running workload is internet exposed, the
effective tier is `edge` regardless of what the file claims. The mismatch itself is reported;
it is a posture finding.

## How exposure is checked

**Layer 1: static, from the manifests in the repo. Zero auth, deterministic, testable offline.**
For a GitOps-managed workload the repo's `app/k8s` *is* the deployment, so exposure can be
**derived from code** instead of self-declared:

| Signal in the manifests | Meaning |
| --- | --- |
| namespace / label scope (`x-mdc-blocked`, `x-mdc-allowed`, `demo-ops`) | whether the admission rule evaluates the workload |
| a `Service` of `type: LoadBalancer`, or an `Ingress`, targeting this workload | internet-facing by construction |
| `hostNetwork`, `privileged`, `hostPath` in the pod spec | escape and blast-radius risk |
| the `serviceAccountName` and its bindings, or a workload-identity annotation | identity reach |

Because Flux deploys exactly these files, intent equals reality for this workload. This is the
primary check and it runs in every pipeline with nothing but the checkout. Its limit: a
workload deployed by some other path may have its manifests elsewhere, which is what layer 2
is for.

**Layer 2: Azure Resource Graph, and what it can and cannot tell you.** The OIDC identity
the pipeline already has, with Reader on the subscription. Be precise about this layer,
because it is easy to overclaim: **in ARG, exposure never appears on its own. It only appears
attached to something**, a risk factor on a finding, or an attack path. So ARG gives two
signals, neither of which is a plain "is this workload exposed" answer.

*Signal A, escalation: is the running version in a validated attack path?*

```kusto
securityresources
| where type == "microsoft.security/attackpaths"
| where subscriptionId == "<sub>"
| extend name = tostring(properties.displayName),
         risk = properties.riskCategories,
         impact = tostring(properties.potentialImpact),
         entities = properties.graphComponent.entities
| where tostring(entities) has "<aks cluster resource id>" and tostring(entities) has "<workload or namespace>"
| project name, risk, impact
```

Read this **only one way**. A row means Defender has validated an externally reachable,
exploitable path through this workload: effective tier becomes `edge`, the finding is
block-unless-exempt, and `riskCategories` / `potentialImpact` go into the summary. **An empty
result means nothing.** Defender emits an attack path only when a weakness, exposure and a
target coincide; a clean, fully internet-exposed workload has no attack path at all. Never
treat "no attack path" as "not exposed".

*Signal B, history: what did the previous version's findings look like, with fix status?*

```kusto
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where properties.additionalData.assessedResourceType has "Container"   // running-container VA
| where tostring(properties.resourceDetails.id) has "<aks cluster resource id>"
| where tostring(properties.additionalData) has "<acr login server>/aks-webapp"   // join key
| project cve = tostring(properties.id), severity = tostring(properties.status.severity),
          patchable = properties.additionalData.patchable, details = properties.additionalData
```

This is the previous version's findings, scoped to this cluster and this image repository.
Where the risk-prioritized recommendation carries an "Internet exposed" risk factor, it is
attached to these findings, and only to them: **a clean previous version has no finding and
therefore no risk factor to read.** The portal's **Open query** on the running-containers
recommendation generates the authoritative form of this query for your tenant; use it as the
source of truth for field names, since Defender is moving from grouped sub-assessments to
per-recommendation `securityFindings`.

**The join key** between the pipeline and the graph is the image. The pipeline stamps
`org.opencontainers.image.source` and `.revision` on every build, and Defender's
code-to-runtime mapping ties image to repo to running workload. In practice the filter is the
ACR repository name, `<acr>/aks-webapp`, plus the cluster resource id.

**Layer 3: the only findings-independent observed exposure, the Exposure Graph.** Advanced
Hunting's `ExposureGraphNodes` carries an explicit `NodeProperties.rawData.exposedToInternet`
per node, computed from control-plane configuration and network-path reachability regardless of
whether the node has any finding, and `ExposureGraphEdges` lets you graph-match from the
workload to what it can reach. This is the one programmatic source that answers "is the running
version of this workload exposed" for a clean image. It is reached through the Microsoft Graph
security hunting API and needs an app permission (`ThreatHunting.Read.All`) rather than Azure
RBAC. If observed exposure matters to you beyond escalation, this is the layer to wire, not a
nice-to-have. The Cloud Security Explorer shows the same insight interactively in the portal.

**When nothing has shipped yet.** Say it plainly: **a workload that has never shipped in any
version is in no graph at all.** Not in ARG, not in the Exposure Graph, not in the Cloud
Security Explorer. There is nothing to observe because nothing exists. Two facts make that a
rule rather than a hole:

- Defender's exposure analysis does **not** need a vulnerable image, it is about the network
  path to the running workload. But be exact about where that answer is readable for a
  *previously shipped* version. Through **ARG** it is not: a clean previous version has no
  finding and no attack path, so ARG returns nothing. Through the **Exposure Graph** (layer 3)
  it is: `exposedToInternet` is set on the node whether or not it has findings. So "observed
  exposure for a clean previous version" exists only if layer 3 is wired.
- Exposure is a property of the **deployment target**, not the image. A never-deployed image
  has no exposure; its *intended* deployment does, and for GitOps that intent is in the repo.

So for a brand-new workload the order of authority is: **layer 1 decides** (the manifests say
where it is going and whether a LoadBalancer or Ingress faces the internet); the **cluster
gate enforces** at admission with the per-tier rule, because it sees the real target; and after
the first deploy the **graph validates** reachability and feeds the next build. The pipeline
never had to guess, it read the manifests.

If there are **no manifests in the repo either** (the workload is deployed by some other path
the pipeline cannot see) and no declared tier, exposure is *unknown*. Unknown is handled
conservatively without becoming an outage generator: fixable findings are treated as `edge`
(block, because the fix is one line away), unfixable findings are audited with an "exposure
unknown, declare a tier" flag, and the cluster gate remains the enforcing point. Unknown never
silently means allow.

**Merge rule.** `effective_tier = max(layer1, layer3_if_wired)`, then **escalated to `edge` by an attack-path hit** (layer 2 signal A). Layer 2 signal B contributes findings history and fix status, not exposure. For a never-shipped workload the input is layer 1 alone, by definition. Reality beats intent.
between the manifests and the graph, the manifests say internal and the graph shows an attack
path, is itself reported as a posture-drift finding, because it means the workload is more
exposed than its code claims.

## The decision engine (deterministic, no model in the loop)

For every finding:

```
effective_tier = max(declared.tier, observed.tier)          # reality beats intent
if active_exemption(cve, scope):                             AUDIT  (reason: exempt, expiry shown)
elif fix_available and severity >= tier.block_at:            BLOCK  (fixable: fix it, no risk argument)
elif not fix_available:
    if tier == edge and (exploit_known or severity == critical): BLOCK-UNLESS-EXEMPT
                                                              (needs a dated break-glass exemption)
    else:                                                     AUDIT + exemption request drafted
else:                                                         AUDIT
if fix_status == unknown:                                     AUDIT + flag "verify fix status"
verdict = worst(findings);   force_push turns BLOCK into BYPASSED, on the record
```

`tier.block_at` comes from the decision matrix: edge = high, internal = critical, sandbox = never.

The job summary shows one row per CVE: severity, fix, exploit, declared tier, observed tier,
exemption, decision, and the one-line reason. That table is the artifact a reviewer, an auditor
and the talk audience all read.

## Where it runs

A `risk-gate` job in `atlas-ci` between the image scan and the push. It needs: the SARIF from
the scan job (artifact), `security/exposure.yaml` from the checkout, the OIDC login (already
there) with Reader for the ARG and exemption lookups, and the Defender CLI auth it already has.
It never needs cluster credentials. The cluster gate stays as the second, security-owned dial
for whatever the pipeline let through or was bypassed on.

## The agentic layer: explain and draft, never decide

Yes to an agentic use case, with one governance rule that makes it defensible on stage:
**the model explains and drafts; the deterministic rules decide.** An LLM must not be the
admission gate. It is non-deterministic, and it is prompt-injectable through the very
artifacts it reads (a CVE description, a package README, a commit message). Defender for AI
Services would raise an alert on such an injection attempt, which is a nice thing to be able
to say, but the right answer is that the gate never took the model's word for anything.

What the agent does, from the structured facts the engine already computed:

1. **A risk narrative for the PR**: three sentences a developer reads. "CVE-X is fixable, bump
   `libfoo` to 1.4.2. CVE-Y has no patch; the workload is internal, not internet exposed, low
   blast radius; an exemption request is drafted."
2. **Drafted exemption justifications** for the no-patch and mitigated cases, with the exploit
   vector named and a proposed review date, ready for a security reviewer to accept in Defender.
   The human accepts; the agent never creates the exemption.
3. **Proposed compensating controls** as ready-to-apply YAML for no-patch cases: a
   NetworkPolicy, `securityContext` hardening, dropped capabilities.
4. **The fix itself, for fixable findings**: this is the path Microsoft already documents.
   Defender generates the GitHub issue with SDLC context, the issue is assigned to the GitHub
   Copilot coding agent, the agent opens the fix PR, Defender marks the issue closed on merge.

The model to use is the lab's own Foundry deployment, called with the pipeline's identity, no
keys. It ties the AI part of the talk back into the pipeline: the same model the lab protects
helps triage. Microsoft's own direction here is the Defender portal's agentic code security
connector (private preview), which runs on-demand agentic scans of onboarded repositories.
Worth one sentence on stage as where this is heading, not a demo beat.

## Honest limits

- **Fix status field names** in the Defender CLI SARIF are the one thing not verified offline.
  The adapter treats an unknown fix status as AUDIT with a "verify" flag, never as a silent
  allow. One authenticated scan will settle the schema.
- **ARG cannot answer "is it exposed" on its own.** Attack paths are escalation-only (present
  means edge, absent means nothing) and risk factors exist only on findings. The only
  findings-independent programmatic exposure attribute is the Exposure Graph's
  `exposedToInternet`, behind the Graph hunting API, and even that has nothing for a workload
  that never shipped. An earlier draft of this document used attack paths as an exposure
  check; that was wrong and is corrected here.
- **Observed exposure is of the previous version.** A change that adds a public Service in the
  same PR is invisible to the pipeline; the declared file plus the cluster gate plus the graph's
  next exposure calculation catch it. This is why the pipeline is a dial, not the only gate.
- **Exemption lookup requires the scope to match**: the exemption must be recorded against the
  image digest, the workload, or the CVE with a scope the pipeline can resolve.
- **The agent output is advisory.** If the model is down, the gate still runs; the summary just
  lacks the narrative.

## The short version

"The pipeline decides two things. If there is a patch, we block, because the fix is one line
away and there is nothing to argue about. If there is not, we do not guess: we ask the security
graph how the last version of this exact workload is exposed, we honor the exemptions security
already recorded, and we let a model write the explanation, but never the verdict."
