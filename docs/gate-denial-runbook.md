# Runbook: a deployment was denied by gated deployment. Now what?

First, the framing, because it changes how the team reads every denial that follows: **a
denial is the safety net working.** It is the image a developer pushed past the pipeline, with
a checkbox, with a skipped scan, or with no pipeline at all, being stopped by the one gate the
team does not own. That is the outcome the whole architecture exists to produce.

Second, the reason this runbook exists: the gate only survives production if a denial has a
fast, boring, pre-agreed path. The first blocked hotfix with no path ends with someone
switching the rule off, and then the safety net is gone. This is the path. It
applies the decision model in `docs/cve-decision-model.md` at the moment it bites.
Verified against Pit's gated-deployment post and Microsoft Learn on 2026-09-18.

## 0. How a denial shows up, and who sees it

| Where | What it looks like | Who |
| --- | --- | --- |
| `kubectl` / Helm | `admission webhook "defender-admission-controller.mdc.svc" denied the request: … Verifier rule name: <rule>` | the deployer, immediately |
| Flux | **only with `wait: true`** on the Kustomization: reconciliation fails, `az k8s-configuration flux show` says Non-compliant, `make flux-status`. Without it Flux reports **Ready** while no pod starts - see below | the deployer / platform, within one sync interval |
| CD pipeline | red deploy stage with the same text | the deployer |
| Defender for Cloud | Environment settings > Security rules > **Admission monitoring** | security |
| Defender XDR | `CloudPolicyEnforcementEvents` with `ActionType == "Deny"`; `CloudAuditEvents` carries the webhook's `ResponseMessage` | SOC / security |

**The GitOps false green.** The gate is an admission webhook on POD creation, so a Deployment
and its ReplicaSet apply cleanly and Flux reports success. The denial lands in ReplicaSet
events, which nobody watches. `wait: true` (set in `infra/modules/flux.bicep`) makes Flux
health-check what it applied, so the Kustomization actually fails. Then push it to where the
app team already is: `app/k8s/40-flux-notifications.yaml` writes a **GitHub commit status**
on the offending commit - idempotent, so a hundred retries are one red check - and posts to a
chat webhook with the storm controls described in that file.

**Route it to the owner automatically.** A custom detection on `CloudPolicyEnforcementEvents`
(Deny, by namespace or rule name) notifies the owning team channel, and Defender's
recommendation owner assignment already knows who that is. A denial nobody is told about is
a denial that gets worked around.

## 1. Triage in five minutes: read the denial, pick the branch

The denial text tells you the rule and the reason. There are exactly five branches.

| The denial says | It means | The branch |
| --- | --- | --- |
| `Unscanned images are not allowed` / no findings artifact | the image has no signed findings on its digest yet | **A. Not a CVE problem** |
| CVE(s) at/above the rule's severity, **fix available** | the base image or a dependency has a newer version | **B. Fix it** |
| CVE(s), **no fix available** | nothing to bump yet | **C. Non-patchable** |
| CVE(s), you have a control that closes the vector | vulnerable image, closed path | **D. Mitigated** |
| the workload should not be under this rule at all | wrong namespace / wrong scope | **E. Placement** |

### A. Unscanned: not a CVE problem
Pushed seconds ago and the scan has not finished, pushed to an unsupported registry, or the
findings artifact was not published. Check the image's **Referrers** in ACR for the signed
findings artifact. Wait for the scan, or re-push to a supported registry. Do not exempt. If
this happens often, the pipeline pushes and deploys too close together; add a wait-for-scan
step. Remember: a missing artifact is **not** a clean image.

### B. Fix available: fix it. This is the default and the fast path.
Bump the base image or the dependency, rebuild, redeploy. Team Atlas's pipeline would have
caught this at gate 1 before an image existed; for a team without that pipeline this is the
moment they learn. Target: minutes to hours. **No exemption.** If someone asks for an exemption
here, the answer is the one-line fix.

### C. No fix available: do not block the team, record the decision
1. Confirm with the finding's fix status (MDVM shows it).
2. Record a **Non-patchable exemption** with a review date: on the gate rule (CVE or resource
   exemption, time-bound) and in Defender's central exemptions (condition Non-patchable, CVE,
   scope = the image digest or workload).
3. Reduce blast radius meanwhile: stricter NetworkPolicy, dropped capabilities, read-only
   filesystem, or move the workload to a less exposed tier if it does not need the edge.
4. Redeploy. Runtime detection (drift, threat) is the backstop.
5. When the fix ships, the finding's fix status changes, the review comes up, branch B.

### D. Mitigated by a compensating control: prove the vector, then exempt
Name the CVE's exploit vector and the control that closes it (a WAF rule for a request-borne
vector, network isolation, auth in front). If the control does not cover the vector, this is
not branch D. Record a **CVE exemption** with the control named and a review date. The CVE
stays visible in the graph so a change in exposure reopens it.

### E. Wrong placement: fix the scope, not the CVE
An internal batch job that ended up in the edge namespace, or a rule scoped too wide. Move the
workload to its tier, or fix the rule scope. The gate did its job; the map was wrong.

## 2. Break-glass: the incident hotfix

The case that kills gates. An incident is running, the fix image carries an unrelated high in
the base image, the gate denies it. The path must be **faster than the incident**:

1. On-call security approves a **time-boxed resource exemption** on the gate rule for that
   workload. Target approval time: under 15 minutes, 24/7. Maximum expiry: days, not weeks.
2. The exemption carries the incident ticket as justification. It is the risk-acceptance record.
3. Redeploy. The hotfix ships.
4. A follow-up ticket is created automatically to remove the base-image finding (branch B)
   before the exemption expires. When it expires, the gate closes again on its own.

Never: disable the rule, delete the rule, widen the rule's scope, or a permanent exemption.
Each of those turns one incident into a standing hole.

## 2b. When it keeps failing: escalate on the signal, not on goodwill

A first denial is triage. The **same team, denied on the same image, for the third time in an
hour** is a different event: the fast path did not work and nobody has asked for help. Left
alone that ends in `--force`, a disabled rule, or a workload quietly moved to a namespace
where the gate is only auditing. So the repetition itself has to raise the request.

### Make the denial self-routing

The denial text the developer sees carries the **rule name** and nothing else you control:

```
admission webhook "defender-admission-controller.mdc.svc" denied the request:
... Verifier rule name: deny-critical-edge
```

So put the escalation path *in the rule name*. It is the only field that reaches the person
who is blocked, at the moment they are blocked:

```
deny-critical-edge--exception-via-sec-exceptions-channel
```

Ugly, and worth it: no lookup, no wiki, no guessing which team owns the gate.

### Detect the repeat, not the single denial

A custom detection on the admission events turns repetition into a ticket. Escalate on
distinct attempts, not raw event count, so one retry loop does not page anybody:

```kusto
CloudPolicyEnforcementEvents
| where Timestamp > ago(1h)
| where ActionType == "Deny"
| extend AF = parse_json(AdditionalFields)
| summarize Attempts = count(),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Rules = make_set(Reason, 5)
        by AzureResourceId, KubernetesNamespace, ResourceName
| where Attempts >= 3 and LastSeen - FirstSeen > 10m
```

Ten minutes apart matters: it separates a human retrying after an edit from a controller
hot-looping. Flux makes this louder, not quieter - a denied `Kustomization` retries every
sync interval forever, so for GitOps the trigger is a reconciliation failing for longer than
two intervals.

### What the escalation creates

Not an email. An **exception request** with the evidence already attached, so the security
conversation starts from facts:

| Field | Filled from |
| --- | --- |
| workload, namespace, tier | the admission event |
| image digest | the admission event - not the tag, the digest |
| rule and reason | `Verifier rule name`, the CVE list |
| owner | Defender's owner assignment for the recommendation |
| attempts, first/last seen | the detection above |
| proposed branch (B-E) | the requester, from section 1 |
| compensating controls | the requester |
| proposed expiry | the requester |

That is the same content as the `risk.acceptance/*` annotations in
`app/k8s/x-mdc-allowed/deployment.yaml`. Generate the annotation block from the ticket and the
two records stay consistent by construction.

### Enforce the review in git, not in a meeting

The acceptance annotations are the one part of a manifest a team must not merge alone. In the
**application** repo:

```
# .github/CODEOWNERS
# Anything claiming accepted risk needs security on the review.
/k8s/**/risk-acceptance.yaml   @contoso/cloud-security
```

Plus a branch-protection rule requiring code-owner review. A team can still propose an
acceptance in a pull request at 23:00; they cannot merge it alone. That is the same asymmetry
as the exemption itself, expressed where the developer already works.

### Escalation ladder

| Trigger | Goes to | Target |
| --- | --- | --- |
| first denial | the deployer, via the denial text | self-serve, branch A/B, minutes |
| 3 denials, same digest, > 10 minutes apart | owning team channel + exception request created | response same working day |
| exception request open > 1 working day, or Flux non-compliant > 2 sync intervals | cloud security queue, named reviewer | decision within one working day |
| incident hotfix blocked | on-call security, break-glass (section 2) | under 15 minutes, 24/7 |
| repeat exception requests for the same CVE across teams | platform backlog: fix the base image once | the real fix |

That last row is the one that pays. Three teams asking for the same exemption is not three
exceptions, it is one unpatched base image, and the escalation data is what makes that
visible.

## 3. Roles, SLAs, guardrails

| Item | Decision |
| --- | --- |
| Who can request an exemption | the workload owner (from Defender's owner assignment) |
| Who can approve | security, with an on-call rota for break-glass |
| Maximum exemption expiry | break-glass: days; Non-patchable / Mitigated: a review date, renewed only with a new assessment |
| Review cadence | every expiry is a review; no silent renewals |
| Where the record lives | the gate rule's exemptions **and** Defender's central exemptions; nowhere else |
| KPIs | deny rate per tier, time-to-unblock, active exemptions and their ages, exemptions expired without removal |

Guardrails that keep the gate credible:

- **System namespaces are excluded** (`kube-system`, `flux-system`, `mdc`). The gate must never
  block the platform, including its own admission controller.
- **New rules start in Audit.** Watch `CloudPolicyEnforcementEvents` for one to two weeks, see
  what would have been denied and whether the owners could have handled it, then flip to Deny
  per tier, edge first.
- **Admitted before the rule means not re-evaluated.** The gate only judges admission requests.
  Existing workloads are covered by runtime vulnerability assessment and drift, not by the gate.
  Know which workloads would fail if redeployed today.
- **Monitor the admission controller.** If the Defender admission pod is down, image gating
  does not run. A gate you cannot see is a gate you cannot trust; alert on the pod and on a
  drop in enforcement events.
- **Order of evaluation.** Misconfiguration policies (VAP) run before the image webhook. A pod
  rejected for `privileged: true` never reaches the image gate; fix the manifest first, then
  expect the image decision.

## 4. Close the loop

Every denial that is not branch A or E ends in a fix at the source. The finding becomes a
GitHub issue with SDLC context assigned to the owner, a PR lands, the new digest passes the
gate on the first try, the exemption expires or is removed, and Defender shows the
recommendation resolved. That is the fix-at-source loop, and it is the only ending a denial should
have.

## The short version

"A denial is not a failure of the pipeline. It is a decision that has been moved to the one
place it can be made correctly, and it comes with a five-minute triage and a fifteen-minute
break-glass. The developer's dilemma at the gate is the same as the analyst's dilemma at
response: both need context, and both get it from the same graph."
