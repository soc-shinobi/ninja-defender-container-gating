# Demo storyline: Shift-Left Is Great, Until Your App Owners Haven't Heard of It

Central code-to-runtime container security with Microsoft Defender for Cloud.
Audience: security engineers and architects. 40 minutes talk, 10 minutes Q&A.
Status: storyline v2, 2026-10-08 (rebalanced toward the abstract: central-first, Ship-It's digest as the single hero, the loop as the payoff). Product claims verified against Microsoft Learn on 2026-09-18.

---

## 1. The one sentence

Every layer from laptop to SOC is a place where a human made a mistake this morning.
Defender for Cloud is the layer that was not asked to trust anyone.

## 1b. Why this topic is under-discussed: nobody owns it

Say this early. It is the hook, and it is better than "here is Defender for Containers".

Identity has an owner in the security team. So does endpoint. **Kubernetes does not.** The
platform team owns the cluster, the application teams own the images, security owns neither
and gets the incident. That is why a room full of experienced security people has thought
less about container supply chain than about conditional access: there is no job title in the
room that obviously covers it.

That gap is the thesis of the talk in one line: **admission control is the one place security
can own a decision without owning the pipeline or the cluster.**

Two framing rules that follow from it:

- **This is an operating-model talk that happens to use Defender.** Most sessions in this
  space are feature tours - enable the plan, look at the recommendations, admire a scan
  result. This one starts from an organisational fact (some teams will never adopt
  shift-left) and derives an architecture from it. The bypass motif, the exception process
  and the escalation ladder are the parts nobody can get from a Learn page, so they are the
  parts that must not be cut.
- **Be precise about the novelty.** Container supply chain is discussed constantly at
  cloud-native events. What is rare is bringing that practice into a Microsoft security
  room. Say it that way: it is accurate, and it invites the KubeCon-adjacent people in the
  audience instead of talking past them. What IS genuinely new is gated deployment, which
  reached GA recently enough that most of the room has never seen an admission deny from
  Defender at all.

Timing context for a German audience: "prove what you shipped, and when you fixed it" is
becoming a compliance conversation through NIS2 and the Cyber Resilience Act. The
code-to-runtime evidence chain - signed findings on a digest, admission events, the
recommendation closing itself - lands as governance, not only as engineering.

## 2. Storytelling devices

Use all five. They are what turn a feature tour into a story.

1. **The clock.** Every beat has a timestamp on one Tuesday. Commit at 09:00, registry at 10:00, cluster at 11:00, exploited at 12:00, SOC at 12:30, fixed at 14:00. This is the abstract's "morning commit, production by noon, exploited by lunch" made literal.
2. **The wall.** One slide with nine dark boxes, one per layer: 1 laptop, 2 repository, 3 pipeline scan, 4 central code scanning, 5 registry, 6 admission, 7 runtime posture, 8 runtime protection and response, 9 the loop. After each beat, one box lights up with what it caught. The audience watches the stack fill in. The last slide is the same wall, fully lit.
3. **Two teams, one app.** Team Atlas adopted shift-left. Team Ship-It never heard of it. Both build the same app from the same Dockerfile. The safety net has to catch both, and it does. Never mock Ship-It: they are shipping features, which is their job.
4. **The hero digest.** One image digest, and it is **Ship-It's**: the image built by the team whose pipeline nobody touched. Two builds of the same Dockerfile do not produce the same digest, so the hero must be one build, followed end to end. Atlas's force-pushed image is a separate digest and only ever an aside. Show the hero on every screen: the workflow log, the ACR referrers view, the recommendation, the gate denial, the pod spec, the XDR incident, the GitHub issue. The audience can follow one artifact through the whole chain with their own eyes.
5. **The bypass motif.** Every layer gets bypassed on stage, and the next layer catches it. Laptop hook skipped, push protection bypassed, pipeline gate force-pushed, pipeline absent, registry skipped, gate scoped around. The message writes itself: no single layer is the control, the stack is.

6. **The translation.** The room is identity- and endpoint-native. They will follow the
   story but not the vocabulary, so map it to controls they have already clicked, once,
   early, on one slide:

   | This talk | What they already run |
   |---|---|
   | admission control | Conditional Access, for workloads instead of users |
   | namespace tier | trust level / device compliance state |
   | image digest | file hash - the thing the verdict is attached to |
   | binary drift | tamper detection on a device |
   | isolate pod | device isolation in Defender for Endpoint |

   The last row is the bridge: they know the action, they have just never seen it aimed at a
   pod. Helped by Defender for Cloud now living inside the Defender portal, so cloud posture
   turns up in the console they already work in - recent enough that many have not noticed.

Rule for a security-engineer audience: every portal screen is paired with a CLI output or a KQL query that proves the same thing. No claim without the wire.

## 2b. Cast

| Role | Name | What they stand for |
|---|---|---|
| The mature team | Team Atlas | Shift-left adopters: pre-commit hook, Defender CLI in the pipeline, branch protection |
| The fast team | Team Ship-It | Ships daily, never heard of shift-left, no scanning anywhere |
| The platform team | The cluster owners | Ship the cluster and the policy: namespaces, tiers, gate rules, RBAC. Never build an app image |
| The security team | You, on stage | Cannot rewrite either pipeline, must be safe regardless |
| The analyst | The SOC person at 12:30 | Knows XDR, has never typed `kubectl` |
| The attacker | Off stage | Uses AI to find the gap faster than a sprint closes |

**Two pipelines, not one.** The platform team has its own workflow
(`.github/workflows-samples/platform-deploy.yml`): it scans `infra/` with the Defender CLI,
runs what-if, deploys the cluster, then verifies the gate is actually armed
(`verify-gating-prereqs.sh`). The application teams have theirs. Show both at least once,
because the split is the point - the platform team **writes** the policy (tiers, rule scope,
deny versus audit, exemptions), the app team **meets** it, and neither can quietly change
the other's half. In this repo they share one checkout; in a real organisation they are
separate repositories with separate owners. Say that out loud so nobody thinks the model
needs a monorepo.

A denial means different things to each of them, which is worth a sentence: for the app team
it is *my release is blocked*, every single time. For the platform team it is only
interesting in aggregate - is the gate healthy, is it blocking many teams at once, is the
admission controller even running. Their real alarm is the opposite one: the gate silently
NOT enforcing.

Both teams build the **same sample app**: our own Flask web app, whose main job is an **AKS control panel** (cluster overview, pods, kubectl console) and which optionally gains a Foundry chat window. Same Dockerfile, same base image, same vulnerable dependency. The only difference is the pipeline around it, so every beat is a fair comparison: same failure, different layers catching it.

## 2c. The one finding

Pick one CVE in the base image or a dependency and follow it for the whole talk. The audience should be able to **name the CVE by minute 15**. The hero digest is its fingerprint; the CVE is the character. Everything else (the secret, the misconfiguration, the AI alert) is supporting cast that shows breadth.

## 3. The arc

### Act 0, cold open (3 min, 00:00 to 03:00)

Slide: the dark wall. Say the one sentence.
Then the honest version of the abstract: in an ideal world every app owner runs the loop. In reality adoption is uneven, and the security team is accountable for all of it anyway.
Say the speed line from the abstract once, here, so the clock has a reason: the workloads now carry AI (the control panel itself has a model window), and the attacker off stage uses AI to find the gap faster than a sprint closes. Point-in-time scanning cannot keep up with that; a continuous loop can.
Introduce Team Atlas and Team Ship-It. Show the app running. Show the hero digest: Ship-It's image.

Speaker framing: do not make this anti-developer. Most developers do care about security; the
problem is that caring is not a control. It does not apply uniformly, it is not auditable, it
disappears under deadline pressure, and nobody can prove to a regulator that everyone cared last
quarter. A control is something that still holds when nobody cooperates. Shift-left remains the
cheapest place to fix a problem, but it is an optimisation, not a boundary.

This is why the story needs layered gates and defense in depth. Developer care buys speed and
cheap fixes. Central controls buy certainty. Atlas finds out in ninety seconds in its own
pipeline, on its own terms. Ship-It finds out at a repository, registry, admission, runtime or
SOC layer, where the cost and timing are worse. Both teams remain visible to security, and the
central controls do not care which team a developer belongs to.

### Act 1, the laptop and the repo (2 min, 03:00 to 05:00) — 09:00 on the clock

Failure: Team Ship-It commits a real-looking ACR password in a config file. This act is
supporting cast: it sets up the bypass motif and introduces the CVE, then gets out of the way.
Secrets are not in the abstract; the CVE is.

Live:
- Setup before the act: `make hooks`, then `make plant-secret`. The secret is planted at
  `app/aks-webapp/config/demo.env`, and the path allowlist that used to silence it has been removed.
  The file is deliberately untracked: the hook only scans staged changes, so a secret already in
  history would trigger nothing and the beat could not run. A published lab also should not ship
  a credential-shaped string to everyone who clones it. `make plant-secret` recreates it whenever
  the beat is rehearsed.
- One sentence, no live run: the gitleaks pre-commit hook caught it and the developer re-ran with
  `--no-verify`. Box 1, the laptop, stays dark. A hook is a suggestion. (If someone asks how hard
  the bypass is: the hook does not exist until a developer runs `make hooks`, and `--no-verify`,
  `SKIP=gitleaks`, deleting `.git/hooks/pre-commit` or committing from the web UI all defeat it.)
- `git push` is blocked by GitHub push protection. Developer bypasses with a justification. Box 2, the repository, lights up half. Switch to Defender: the bypass is logged at the org level and shows up in Defender's DevOps secrets findings. Security saw it without being in the room.
- Developer bumps a dependency to a version with a known critical CVE and pins the base image to an old tag. Opens a PR. Branch protection requires one review. Teammate approves in 20 seconds. Merged. Name the CVE now; it is the character for the rest of the talk.
- Backup only, if Q&A asks: deleting is not fixing. Remove the secret and push again, and GitHub Advanced Security secret scanning still alerts on the historical commit; history is the attack surface.

Proof: Defender for Cloud, DevOps security, secrets finding for the repo. GitHub org security overview, push protection bypass entry.

Value line: controls you own at the org level survive individual bypass. Controls on the laptop do not.

If someone asks, “So is this about the developer caring about security?”, answer: “For the local
hook, yes, entirely. Architecturally, no. That inversion is the talk in one sentence. The hook
catches the honest accident cheaply; it cannot catch the person who does not want to be caught.
That is not a criticism of developers. It is why caring cannot be the security boundary.”

Then land the larger point: push protection, branch protection with required checks and Defender's
agentless scanning are controls the developer cannot turn off from a laptop. Registry scanning,
admission policy, runtime detection and response sit further right still. We need both shift-left
and central enforcement: the first makes remediation fast and cheap; the second makes coverage
reliable. Layered gates are not a vote against developers. They are what lets security protect
every team, including the teams that never opted into the earlier layer.

CI/CD strengthened how: secret controls moved from the developer's machine to the platform, where a bypass is logged instead of silent.

### Act 2, the pipeline (5 min, 05:00 to 10:00) — 09:30 on the clock

Failure: Ship-It's workflow builds and pushes with long-lived ACR credentials and no scanning. Atlas's workflow runs the Defender CLI.

Weighting rule for this act: Atlas is the 90-second contrast, Ship-It is the story. The abstract
promises "no pipeline rewrites", so the central half of this act (agentless scanning and
pipeline posture) gets the time, not the in-pipeline gates.

Live, Atlas (90 seconds):
- Atlas workflow: `defender scan fs` and `defender scan image` (MDVM-backed) break on critical. One tool, the Defender CLI, running checkov, template analyzer and trivy under one binary. The job summary names the CVE. On Atlas's side the CVE never becomes an image. Box 3 lights up for Atlas.
- The ratchet, one sentence, from the same job summary: *versus running: +2 new highs, blocked*. You may not ship an image that is worse than the one already running; the previous version's findings are already in the graph. This is what mature teams do, and it is an optimisation, not the control.

Live, Ship-It (3.5 minutes):
- Ship-It workflow log: docker build, docker push, done in 40 seconds, red "no security scanning" summary on the run page. Box 3 stays dark for Ship-It. This build produces the hero digest. Copy it onto the slide.
- The pipeline identity: a step prints the effective role assignments of the OIDC identity the pipeline runs as. Note it out loud. In Act 3 the attack path draws this exact identity as the edge into AKS.
- Switch to Defender: agentless code scanning already has Ship-It's repo. Dependency finding with the CVE, IaC finding for the Dockerfile running as root, SBOM present. Nobody touched Ship-It's workflow. Box 4, central code scanning, lights up.
- DevOps posture: the pipeline itself is flagged. Secrets stored as plain repository secrets, no OIDC, unpinned third-party action. The pipeline is an asset with posture, not just a place where scans run.

Backup only, not in the 40 minutes:
- The risk-gate table (`docs/pipeline-risk-gate.md`): one row per CVE, fixable, exposure, verdict, one-line reason. Use it if Q&A asks how the pipeline avoids block-everything.
- The scanner dropdown: trivy or grype on the same digest for a second opinion.
- Atlas's human bypass (`force_push=true`) is not shown here; it returns as a 60-second aside in Act 4.

Proof: Cloud Security Explorer query, repositories with dependency X. Defender CLI SARIF and the job-summary tables in the workflow run.

Value line: CI/CD security is two things. What runs inside the pipeline, which only the adopters get. And the posture of the pipeline itself, which the security team gets for every pipeline in the org. Then the thesis in one breath: you did not scan Ship-It's pipeline. You scanned the outcome of every pipeline, and you know which one to worry about first.

CI/CD strengthened how: the pipeline is no longer the only place a scan can happen, so a missing scan step is a posture finding rather than a blind spot.

### Act 3, the registry and the graph (7 min, 10:00 to 17:00) — 10:00 on the clock

Failure: the vulnerable image is now in ACR and running on Container Apps, internet exposed, with an identity that can write to the AKS demo namespace.

Live:
- ACR: the hero digest, and its referrers. The signed vulnerability findings artifact attached to the digest. This is what the cluster gate will read later. Then the one sentence for the mature people in the room, 20 seconds: the gate reads this attestation, not a scanner's stdout. That is VEX-style attestation gating, the pattern the most mature shops build by hand with Sigstore and in-toto, and here it is native. Box 5, registry, lights up.
- Say where this chain came from before you walk it: nobody instrumented Ship-It's pipeline. Connecting the GitHub org triggered Microsoft's automated tooling, which in their words does not affect existing DevOps workflows and enables code-to-runtime mapping. One connector, every repo, zero pipeline edits.
- Defender recommendation for the image. Open Remediation Insights. Walk the SDLC chain backwards: running container on ACA, image, pipeline run, repository, commit. Team Ship-It's name is on it.
- All impacted assets: the same digest running on ACA and on AKS. Filter by namespace. This is the blast radius from the abstract.
- Attack path: internet-exposed Container App, critical CVE, identity with write access to AKS. A toxic combination drawn by the graph, not asserted on a slide.
- Exposure, show the wire, 30 seconds: open the Cloud Security Explorer internet-exposure insight for the running workload, or the `ExposureGraphNodes` query with `exposedToInternet`. Point at it: this is where exposure is computed, from network path reachability, not from a public IP flag. When we say block by exposure, this is the number.
- The decision: fix in the Dockerfile, once, and every downstream workload inherits it. Create the GitHub issue **live**, from the recommendation, assigned to Ship-It's CODEOWNERS, with the runtime context attached. Open it in GitHub for ten seconds so the room sees the SDLC context in the issue body. Do not wait for anything to happen. Come back in Act 7. Box 9, the loop, lights up half.

Proof: Cloud Security Explorer, container images containing package X, contained in registries, running on clusters.

Value line: one finding, every affected workload, one owner, one fix. This is the difference between a scanner and a security graph.

CI/CD strengthened how: findings travel with the artifact and map back to the commit, so remediation lands in the repo that produced it instead of in a ticket queue.

### Act 4, the cluster door (6 min, 17:00 to 23:00) — 11:00 on the clock

Failure: the same image reaches AKS through GitOps. Flux syncs `app/k8s` from git on a timer, so no pipeline gate is in the way. Nobody `kubectl run`s to production; this is how it actually happens.

Live:
- Flux reconciles the hero deployment from git. The admission webhook denies the image. Run `make flux-status`: the Kustomization reports the failure carrying the denial text. Read it aloud. The gate sits at the API server, so it catches every deployer, GitOps included. Box 6, admission, lights up.
- Then say what just happened, slowly, because it is the talk: this is Ship-It's hero digest, the one no pipeline ever scanned. Nobody asked Ship-It to change anything. The registry scanned it anyway, and the cluster said no anyway. Every gate a developer can bypass is a suggestion; the admission gate is the first one they cannot, because the team does not own it.
- The Atlas aside, 60 seconds, and keep it respectful: even the mature team can click past its own gate. Show the pre-run atlas-ci run with `force_push=true`: the scan failed, the verdict badge is yellow BYPASSED, the image was pushed anyway. Then `kubectl -n x-mdc-blocked run atlas-check --image=$ACR_LOGIN_SERVER/aks-webapp:latest`: denied with the same text. The team's severity threshold is a pipeline setting; the cluster's gated-deployment threshold is owned by security. The team can lower theirs; they cannot lower yours. It did not matter how the pipeline was bypassed, force_push, skip_scan, or no pipeline at all.
- The same CVE, two namespace scopes: Flux deploys the identical digest to `x-mdc-blocked` and `x-mdc-allowed`. Admission denies Pod creation in `x-mdc-blocked`; `x-mdc-allowed` is outside the rule scope, runs successfully, and is exposed through a LoadBalancer. The contrast demonstrates that admission coverage is only as broad as its namespace selector.
- What happens in production when this hits, one sentence only: `docs/gate-denial-runbook.md` triages every denial into five branches, and most denials are branch B, the one-line fix. Walk the other branches only if Q&A asks.
- Break-glass: show a resource exemption on the edge rule with an expiry date. That is how a hotfix ships during an incident: a dated risk-acceptance record, not a disabled gate. Two more reasons for an exemption belong in the same breath: a CVE mitigated by a compensating control such as a WAF rule that covers its vector (vulnerable image, closed path), and a CVE with no patch available yet, recorded as Non-patchable with a review date. Both are decisions on the record, neither disables anything.
- One sentence on provenance, no demo: an image nobody scanned has no findings artifact, and the rule says unscanned means deny. That is the native analog of provenance gating; an image that did not come through a registry Defender knows is refused before its CVEs are even a question.
- The KPI slide, 30 seconds, the operator's answer: deny rate per tier, time-to-unblock, active exemptions and their ages, share of images on the golden base. This is how you know the gate is alive and not rotting, and it is the slide that answers the architect who is silently asking how you run this.
- Fallback if Flux misbehaves live: `kubectl kustomize app/k8s | envsubst | kubectl apply -f -` produces the same denial by hand.
- Show the wire: the validating webhook config, the securityartifactpolicies CRD, the rule in Defender. Then the KQL on CloudPolicyEnforcementEvents showing the deny event.
- Optional if time: the same manifest with privileged true is rejected by the VAP misconfiguration policy before the image gate even runs. Two layers, same manifest.
- The bypass: `kubectl run` with an image pulled straight from Docker Hub into a namespace the rule does not cover. Admitted. The pipeline never saw it, the registry never saw it, the gate was scoped around it.
- Switch to Defender: registry-agnostic runtime vulnerability assessment already lists the running container from yesterday's cycle. Pre-seeded. Box 7, runtime posture, lights up.

Value line: one team never scanned, the other bypassed its own scan, and the cluster said no to both. That sentence is the abstract. Admission is the last chance to prevent, and it is not one rule for everything: block by exposure, not by CVSS. When even that is scoped around, you still see it. Prevention has gaps by design; visibility must not.

CI/CD strengthened how: deployment policy is enforced at the cluster, owned by security, regardless of which pipeline or GitOps engine did the deploying.

### Act 5, runtime (5 min, 23:00 to 28:00) — 12:00 on the clock

Failure: the workload is exploited.

Live, from the control panel on ACA. Worth one sentence first: the panel drives the cluster by exec-ing into a kubectl pod through the API server, so every command it runs is in `CloudAuditEvents`. A legitimate control plane and an attacker are indistinguishable from the cluster's side, which is exactly why runtime detection has to watch behaviour rather than identity.

Live:
- Drop a binary into the running container and execute it. Drift alert. If time, flip the rule to blocking and run it again, the second attempt fails. Blocking needs the Helm-provisioned sensor (`defenderSensorViaHelm=true` at deploy, then `make sensor-helm`); the AKS add-on gives detection only.
- Run the alert simulation from the panel: tick `binary_drift`, `miner_process` and `network_scan`, press run, watch the log stream. The **re-run** button deletes the Job and starts it again, which is how you re-fire a beat if the first alert is slow. 33 scenarios are available; the quick-wins group is pre-ticked.
- The AI beat, protected: send the jailbreak prompt in the panel's model-inference window. Prompt Shields blocks it, Defender for AI Services raises the alert with the end-user identity from Entra auth on the Container App. This pays off the abstract's opening line about AI riding on containers, so it is not optional: deploy Foundry for the talk, and if it misbehaves live, play the recording rather than skipping it.
- All three alerts correlate into one XDR incident. Box 8, runtime protection, lights up.

Proof: CloudProcessEvents in Advanced Hunting for the drifted process.

Value line: immutable images turn drift into a high-fidelity signal. The AI call is a workload like any other, and it lands in the same incident.

CI/CD strengthened how: the build's output is the runtime's baseline; anything that diverges from the shipped image is a signal the pipeline could never have seen.

### Act 6, the SOC (5 min, 28:00 to 33:00) — 12:30 on the clock

This is the hand-off the abstract's runtime layer depends on: detection is only worth what the
analyst can do with it. The abstract does not name the SOC, so keep this act tight and let
the loop in Act 7 be the payoff. Budget: terminate versus isolate 2 min, hunting 1 min,
identity beat 1 min, incident framing 1 min.

Live:
- Open the incident in the Defender portal. Incident graph: user, Container App, pod, cluster, image. The hero digest again.
- The analyst's dilemma. Say it plainly: most SOC analysts have never run kubectl. They see three buttons.
- Click Terminate pod. Watch the ReplicaSet recreate it within seconds. The attacker's foothold is gone, the vulnerable image is back. Nothing was fixed.
- Click Isolate pod. Network policy applied, traffic stops, the pod stays for forensics. This required a network policy engine on the cluster, which was a platform decision made months ago, not an analyst decision made now. Box 8 now carries response as well as detection.
- Go hunt from the incident (never cut). Show the process tree, then the `CloudProcessEvents` query for the drifted process. This is the "no claim without the wire" proof for runtime, and it is the step an endpoint-native analyst already knows how to do.
- If licensed and time allows: Security Copilot guided response for the same incident, which tells the analyst what each action will do before they click. First thing to go when the clock slips.

**The identity beat (do not skip this one for an identity-native room).** Show a
workload-identity alert next to the container alert: *Suspicious invocation of a high-risk
'Credential Access' operation by a service principal*. In this lab it fires for real, and the
service principal is **ours** - the control panel's managed identity calling
`listClusterUserCredential` to fetch the cluster CA so it can talk to the API server.

Say it exactly like that: the defender's own tooling looked identical to an attacker, because
from Defender's side it is the same shape - a workload identity reaching for cluster
credentials. Then walk the chain the room already understands from their own world: pod ->
workload identity (federated, no secret) -> Azure resource. That is the pivot container
attackers actually use, and it is the moment the talk connects to the identity people's
day job.

Value line: response actions are not the control. Understanding the blast radius of the response is the control. The incident has to carry the Kubernetes context, because the analyst will not.

CI/CD strengthened how: the same identities and images the pipeline produced are the entities the SOC acts on, so response reaches the workload without a hand-off to the platform team.

### Act 7, close the loop (6 min, 33:00 to 39:00) — 14:00 on the clock

This is the abstract's payoff. It gets real time and ends on something live, not a screenshot.
One minute of buffer remains after it (39:00 to 40:00).

Pre-seeded from a run three days earlier on the Ship-It hero digest (the status sync can take up
to 24 hours, so this part cannot be live):
- The GitHub issue, assigned to Ship-It's CODEOWNERS, carrying the SDLC context. Same shape as the one created live in Act 3.
- The PR that changed one line in the Dockerfile. Merged.
- The issue closed, and the recommendation in Defender showing resolved, synced from GitHub.

Live:
- The fixed Ship-It digest is already in ACR from the pre-seed run. Point the hero deployment at it (merge the pre-staged manifest change, or `make flux-status` after a reconcile) and let Flux sync. The same gate that denied Ship-It at 11:00 admits them now, first try. Read the admission event, or the `CloudPolicyEnforcementEvents` row, aloud. Box 9, the loop, lights up fully.
- Fallback if Flux is slow: `kubectl -n x-mdc-blocked set image deployment/webapp webapp=<fixed digest>` gets the same admit.
- One sentence on where the fix lands: it landed in the base image, so every workload built from it inherits the fix on its next build. Mature shops make that an owned program, a platform team rebuilding golden bases on a cadence. Fix once at the source is an org chart, not a slogan.

Slide: the wall, fully lit. Ship-It never changed their pipeline. Atlas kept theirs. Security scaled anyway.

**The take-home (30 seconds, do not cut this).** One link: `workbooks/` in the repo - an AKS
cluster fingerprint workbook, 56 panels, pure Defender XDR advanced hunting. Nothing to deploy,
no workspace, no ingestion: paste the JSON into the Defender portal and point it at a cluster
they already run. It answers what runs here, what the gate decided, who touched the API server,
which identities reach Azure from a pod, and which CVEs sit on images that actually execute.
Say the honest line: nobody rebuilds a demo lab on Monday - but everybody can paste a workbook
into a portal and look at their own cluster before lunch.

CI/CD strengthened how: the fix landed in the pipeline that caused it, and the platform reported it resolved without anyone filing anything. Security scaled without touching Ship-It's pipeline.

End on the one sentence.

## 4. The value map

Say each of these once, at the moment the demo proves it, never as a list at the end.

| Layer | What Defender for Cloud gives the security team | What it changes for CI/CD |
|---|---|---|
| Repo | Org-wide secrets and posture findings, including bypasses | Bypass is visible, not silent |
| Pipeline | Defender CLI for adopters, agentless scanning for everyone, the ratchet against the running version | Coverage does not depend on adoption, and no image may ship worse than what runs |
| Pipeline posture | Pipelines and service connections assessed as assets | The pipeline is in scope, not just the code |
| Registry | Scan on push, signed findings attached to the digest | Findings travel with the artifact |
| Graph | SDLC chain, impacted assets, attack paths | Fix once at the source, with an owner |
| Admission | Deny by vulnerability policy, security owns the rule, catches what the pipeline was bypassed on | Policy enforcement without a pipeline step, and the first gate a developer cannot click past |
| Runtime posture | Registry-agnostic scanning of running containers | Even bypassed artifacts are seen |
| Runtime protection | Drift, sensor detections, AI alerts in one incident | Detection where prevention had gaps |
| SOC | Pod-level response in XDR | Response reaches the workload, with context |
| Loop | GitHub issue with runtime context, status sync | The fix lands where the code lives |

## 5. What is deliberately not in the 40 minutes

- Malware detection and node scanning. Breadth without a new failure mode.
- The Foundry agent mode. Show the toggle, say the licensing line, do not demo it. Agent-level detection needs Agent 365 and a published agent.
- Image signing with Notation and Ratify. Real control, different product story.
- Sentinel playbooks and automated isolation. Automation would hide the analyst dilemma you want the audience to feel.
- The compromised-developer-identity incident. Excellent stack story, but it needs Entra ID Protection and adds a fourth actor. Keep it for the Q&A or a follow-up post.
- Image signing and provenance with Sigstore, SLSA or Ratify verification. The right pattern and the wrong talk; the unscanned-means-deny sentence in Act 4 is the native analog.
- A golden-base-image program. One sentence in Act 7, not a beat.
- A second unscanned-image beat. The denial text already says it.
- Calling the model live for the agentic narrative. Latency on stage is not a story; it is shown pre-seeded.

## 6. Cut order if rehearsal runs long

Timing budget (40 min): Act 0 3, Act 1 2, Act 2 5, Act 3 7, Act 4 6, Act 5 5, Act 6 5, Act 7 6,
buffer 1. If the slot turns out to be 45 minutes including Q&A, drop Act 1 entirely and open
Act 2 with the push-protection bypass in Defender's DevOps findings.

1. Act 6 Security Copilot guided response.
2. Act 4 VAP misconfiguration gate.
3. Act 4 Atlas aside. Keep the one sentence ("even the mature team can click past its own gate, and the cluster says no to them too"), drop the screens.
4. Act 4 Docker Hub bypass. Narrate, show the pre-seeded recommendation.
5. Act 3 exposure show-the-wire. Keep the sentence, drop the screen.
6. Act 2 ratchet sentence.

Never cut:
- Ship-It caught without any pipeline change (Act 2 agentless scanning and posture, Act 3 registry).
- Act 3 blast radius and the owner-assigned issue.
- Act 4 the hero digest denied at admission.
- Act 5 the AI beat. Play the recording if live fails; do not drop it.
- Act 6 terminate versus isolate, and hunting from the incident.
- Act 7 the loop, ending on the live admit.

**Nor the operating model.** With three demos in a 40-minute slot, the first thing that gets
squeezed is the part that is not on a screen: the ownership premise, the denial path, the
exception process, the close. That is exactly the differentiator - it is what a senior
audience cannot get from a Learn page - so rehearse with the gating-strategy slide and the
close treated as fixed, and shorten **Act 6's incident framing** instead if the clock slips
(terminate versus isolate and hunting stay).
A demo that runs two minutes short and lands the operating model beats a demo that fills
the slot and ends on a product screen.

## 7. Pre-seeding checklist

Everything with latency runs days before, and the demo shows the result.

| Item | Latency | Seed when |
|---|---|---|
| GitHub connector (**do this FIRST**: images built before connecting may map poorly) and agentless code scanning of both repos | daily scan, 15 to 60 min per run | 3 days before, before any image build |
| DevOps posture for pipelines | every 8 hours | 2 days before |
| ACR scan of hero digest and findings artifact | minutes to hours | 2 days before |
| Registry-agnostic runtime VA of the Docker Hub pod | daily | 2 days before |
| Attack path for ACA identity to AKS | up to 24 hours | 3 days before |
| GitHub issue, PR, closed, resolved sync, all on the **Ship-It** hero digest | up to 24 hours | 3 days before |
| Fixed Ship-It digest pushed and scanned clean, manifest change pre-staged for the live admit in Act 7 | minutes to hours | 2 days before |
| Atlas `force_push=true` run, for the Act 4 aside | one pipeline run | 2 days before |
| AI alert end-user context and prompt evidence | minutes | rehearse day before |
| A cleaner previous version running, so the force-pushed image is measurably worse for the ratchet | one deploy | 2 days before |
| The agentic job summary from an earlier run: risk narrative + drafted non-patchable exemption | one pipeline run | 2 days before |
| Fallback recordings of every live beat | none | 1 week before |

## 8. Open verifications before the talk

0. Slot length at Workplace Ninjas: 40 + 10 or 45 total. The cut order in section 6 has the 45-minute variant.

1. Whether a jailbreak sent through the Foundry agent still triggers the model-layer Prompt Shields alert from Defender for AI Services. Test in tenant.
2. Whether the isolate action works on the chosen network plugin at the cluster version deployed by the IaC. Test after every AKS upgrade.
3. Exact wording of the gate denial for an image with findings versus an unscanned image. Use the version that matches the rule you demo.
4. GitHub issue status sync timing on the day. Have the pre-seeded example ready regardless.
