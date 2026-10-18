# Defender for Cloud: code-to-runtime demo lab

A shareable demo lab for **container and CI/CD security with Microsoft Defender for Cloud**, built around one story: *shift-left is great, until your app owners haven't heard of it.* Two teams build the same vulnerable app. One adopted shift-left, one did not. Every layer from laptop to SOC catches what the layer before it missed, and none of it touches an app owner's pipeline.

Focus is **defense in depth, left to right**. No WAF, no App Gateway, no ingress edge security. That is a separate topic and is deliberately out of scope.

> Product behavior verified against Microsoft Learn on 2026-09-18. Some features used here are in Preview (XDR pod response actions, agentless code scanning). Treat this as a lab, not a support statement.

## What you get

| Path | What it is |
| --- | --- |
| `docs/architecture.md` | ASCII architecture + coverage matrix + IaC boundaries + AKS sizing |
| `docs/architecture.svg` | The same architecture as a dark-mode diagram for slides/blog |
| `docs/demo-story.md` | The 40-minute storyline: acts, timing, value lines, cut order, pre-seed checklist |
| `docs/cve-decision-model.md` | How CVEs are handled in production terms: block by exposure not CVSS, namespace tiers (edge / internal / sandbox), the decision matrix, break-glass exemptions with expiry |
| `docs/pipeline-risk-gate.md` | Design of the in-pipeline risk gate: fixable means block, otherwise decide by exposure looked up from the Defender graph for the previous version, honor recorded exemptions; the agentic layer explains and drafts, never decides |
| `docs/gate-denial-runbook.md` | Production runbook for a gated-deployment denial: how it surfaces, five-minute triage into five branches (unscanned, fix it, non-patchable, mitigated, placement), the 15-minute break-glass, roles/SLAs/KPIs, guardrails, and the loop back to the source |
| `docs/scanning-tools.md` | Which tool does image / IaC / secret scanning, and why the DevOps connector is still the way to go (Defender CLI vs MSDO vs connector) |
| `docs/kubectl-command-library.md` | Every kubectl command the control panel runs, grouped by blade, with a one-line explanation each |
| `docs/recent-changes.md` | What changed on 10-11 October 2026 (cleanup, namespace rename, approval gate, Copilot BYOK, CI digest, panel) and what to check when something breaks |
| `infra/` | Bicep: RG, Log Analytics, ACR, ACA + Entra auth, AKS (ephemeral disk, Cilium, Defender gating), Foundry, Flux GitOps (AKS extension), Defender plans |
| `infra/postdeploy/` | `configure-gating-and-drift.sh` (gated rule + drift policy, portal/REST), `install-defender-helm.sh` (Helm sensor for drift blocking), `foundry-agent.sh` (agent publish), `disable-defender-plans.sh`, `connect-github.md` (connector runbook) |
| `.github/workflows/` | This repo's own CI: `deploy-lab`; `aca-webapp` (secure ACA release); `demo-admission-allowed`; `demo-admission-blocked`; `demo-pipeline-scan-blocked`; `validate-bicep`; `copilot-triage` (reusable, optional via the delivery workflows' `copilot_issue` input: GitHub Copilot CLI on a custom Foundry model writes a deduplicated security issue from the scan evidence; Entra ID or API-key auth); `security-defender-scan-only` (report-only Defender CLI image scans of both images, plus a pinned checkov IaC scan of the Bicep and Kubernetes manifests); `destroy-lab`; and `lab-park`. Publishing uses secret/image gates, immutable artifacts, optional GitHub attestations, and the protected `showcase` environment documented in [`docs/showcase-environment.md`](docs/showcase-environment.md). |
| `.github/workflows-samples/` | atlas-ci (one tool: Defender CLI `scan fs` + `scan image`, both break; live-demo inputs: scanner dropdown, `severity_threshold`, `force_push` bypass, `skip_scan`) and shipit-build (no scanning). All workflows carry live-demo formatting: emoji gate names, ANSI-colored log banners, collapsible sections, and a Markdown job summary per gate with findings by severity |
| `app/webapp/` | Flask control panel source. ACR repository `aca-webapp` runs as the ACA control panel (`<namePrefix>-app`). |
| `app/aks-webapp/` | Small Flask dashboard that reads the synthetic blob via workload identity. ACR repository `aks-webapp` runs as Kubernetes Deployment `webapp` in the two AKS demo namespaces. Carries planted vulnerable packages on purpose for the CVE and image-gating beats. |
| `app/mdc-alert-simulation/` | Defender for Containers **alert-triage image**: 33 benign scenarios (drift, miner, network scan, recon, evasion, ...) selected with `SCENARIO`. The control panel runs it as a Kubernetes Job and can re-run it |
| `app/k8s/` | Flux deploys the same vulnerable app twice with separate health checks: `x-mdc-blocked` is selected by the admission deny rule; `x-mdc-allowed` is deliberately outside its scope and exposed by a LoadBalancer. `demo-ops` hosts the panel's runner. |
| `workbooks/` | **AKS cluster fingerprint workbook** (56 panels, Defender XDR advanced hunting, `queryType: 1`): alerts and incidents, admission decisions, runtime behaviour, DNS egress, Kubernetes control-plane audit, exposure-graph attack paths, pod-to-Azure identity reach, and a runtime-filtered CVE rollup. Nothing to deploy - paste the JSON into the Defender portal. This is the take-home artifact for the audience |
| `scripts/` | `deploy.sh`, `build-push-app.sh`, `update-flux-image.sh` (updates one GitOps image reference), `wait-flux-reconciliation.sh` (waits for Azure-reported Flux status), `preseed.sh`, `lab-start.sh` (on-demand start with readiness), `lab-park.sh` (nightly park engine), `destroy.sh` |

## Two teams, two pipelines, one repo

A real organisation has at least two repositories here, owned by different people. This lab
keeps them in one so the demo has a single checkout, but the **boundary is real and the talk
shows both sides of it**.

| | Scenario 1: platform / cluster team | Scenario 2: application team |
| --- | --- | --- |
| Ships | the cluster and the policy around it | a container image |
| Owns in this repo | `infra/**`, `app/k8s/base/**`, `infra/postdeploy/**` | `app/webapp/**`, `app/k8s/x-mdc-blocked/**`, `app/k8s/x-mdc-allowed/**` |
| Sample workflow | `.github/workflows-samples/platform-deploy.yml` | `atlas-ci.yml` (scans) and `shipit-build.yml` (does not) |
| Relationship to the gate | **writes** it: tiers, rule scope, deny vs audit, exemptions | **meets** it: the image is judged on admission |
| Cares about a denial | only in aggregate - is the gate healthy, is it blocking many teams | acutely - my release is blocked |
| Gets scanned by | Defender CLI `scan fs` over `infra/` in its own pipeline | `scan fs` + `scan image`, or nothing at all (Ship-It) |

Two things follow, and both are talking points rather than features:

- **The platform team is a shift-left customer too.** A namespace tier label and a gate rule
  are security policy expressed as code. A typo there is a control gap, so the platform
  pipeline scans its own IaC before it deploys and verifies the gate is armed afterwards
  (`infra/postdeploy/verify-gating-prereqs.sh`). A cluster that deployed is not the same as
  a cluster that is guarded.
- **Neither team can quietly change the other's half.** App teams cannot relabel a namespace
  into a softer tier; the platform team cannot make a vulnerable image acceptable. That
  separation is what makes the gate a control instead of a suggestion.

The public `x-mdc-allowed` AKS application also behaves like a small real workload: it heartbeats
to the ACA control panel and retrieves clearly synthetic confidential customer records from a
private Blob container. AKS workload identity supplies the token, Azure RBAC grants only Blob
Data Reader on that container, and the public page shows both connection states plus the fake
records. No storage key or connection string reaches the pod.

## The eight layers

0. **Developer** - gitleaks pre-commit. Advisory only: it does not exist until someone runs `make hooks`, and it is skippable six different ways. That is the point, not a gap. See [Layer 0: the hook you cannot rely on](#layer-0-the-hook-you-cannot-rely-on)
1. **Repository** - GitHub Advanced Security (push protection + secret scanning), branch policy, plus Defender agentless code scanning and DevOps posture
2. **Pipeline** - [Defender for Cloud CLI](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-cli-overview), one tool: `scan fs` (IaC, code, dependencies) and `scan image` (MDVM), both break the build (Atlas only)
3. **Registry** - ACR image scan on push, signed findings artifact on the digest
4. **Admission** - Defender for Containers gated deployment denies the vulnerable image on AKS, even when Flux GitOps is the deployer
5. **Runtime** - Defender sensor: binary drift, threat detection, malware; Defender for AI Services for model calls
6. **SOC / XDR** - terminate / isolate / restrict pod, and the analyst's blast-radius dilemma
7. **Loop** - finding to GitHub issue to PR to "resolved" synced back to Defender, ending with the fixed digest admitted by the same gate

## Prerequisites

- An Azure subscription where you can enable Defender plans (**Owner**: the template writes role assignments and subscription-scope pricings).
- **Region: `swedencentral`** by default. Why, and what the real constraint is, in [Region choice](#region-choice-swedencentral).
- Azure CLI 2.90+. Also on your machine: `make`, `docker` (for `make app`), `kubectl` (for `make flux-status` and the readiness check in `make lab-start`), `helm` (only for `make sensor-helm`), `pre-commit` (only for `make hooks`), `envsubst` (only for the manual kubectl fallback in `preseed`).
- **Bicep plus the `containerapp` and `k8s-configuration` Azure CLI extensions.** Install them with `make prereqs` (also run by `make deploy`):

  ```bash
  az bicep install                        # infra/*.bicep, infra/main.bicepparam: make validate, whatif, deploy
  az extension add -n containerapp        # every `az containerapp ...`: make app, auth, grant-panel, lab-start/stop
  az extension add -n k8s-configuration   # `az k8s-configuration flux show`: make flux-status
  ```

- `make prereqs` also registers every required provider, including `Microsoft.KubernetesConfiguration` for Flux. `Microsoft.Kubernetes` is not required because this is managed AKS, not Arc.
- A GitHub organization with two repos (Team Atlas, Team Ship-It) that both build `app/webapp`.
- For Layer 5 model alerts: the Defender for AI Services plan (30-day free trial, capped at 75B tokens).
- For Layer 6 isolate/restrict pod: Kubernetes 1.27+ and a network policy engine. This lab ships Cilium, which satisfies it.

## Operate from this repo

Everything runs through `make`. Run `make help` for the full list.

| Command | Does |
| --- | --- |
| `make validate` | Compile all Bicep and run the control-panel checks (no Azure login needed) |
| `make test` | Static checks: control-panel integrity and docs in sync (plain `python3`, no dependencies) |
| `make whatif` | Preview infra changes against the subscription |
| `make prereqs` | Install the Bicep CLI and the required az extensions (`containerapp`, `k8s-configuration`), and register the resource providers |
| `make deploy` | Deploy and verify the complete lab: infra, images, Flux/bootstrap, panel access, policy reconciliation |
| `make deploy-aca` | Deploy only ACA; retry in `ACA_FALLBACK_LOCATION` on a regional-capacity failure |
| `make app` | Build + push the vulnerable app, point the Container App at it |
| `make bootstrap` | Apply `app/k8s` manually when Flux is explicitly disabled |
| `make verify-deployment` | End-to-end verification of AKS, ACA, image/port, runner, RBAC, health and policy state |
| `make auth` | Only with `PANEL_ENTRA_USER=<upn>`: Entra sign-in (EasyAuth) scoped to that one user. Without it the panel already has basic auth |
| `make grant-panel` | Grant the control panel exec rights in `demo-ops` (namespace-scoped AKS RBAC Writer) |
| `make heartbeat` | Re-point the AKS web app heartbeat at the panel's current hostname (re-runs the Flux configuration; normally automatic) |
| `make sensitive-storage` | Seed synthetic confidential Blob records and connect the public AKS web app through workload identity |
| `make gating` | Configure the gated rule + drift policy (portal/REST helper) |
| `make verify-gating` | Check the four gated-deployment prerequisites (sensor, Security Gating, Registry access, **Security findings**) and report gaps |
| `make connect-github` | Print the GitHub connector runbook |
| `make foundry-agent` | Publish the Foundry agent (chat mode B) |
| `make flux-status` | Flux GitOps compliance state + Kustomization (the Act 4 denied-by-gate beat) |
| `make sensor-helm` | (Re)install the Defender sensor via Helm. `make deploy` already does this by default; use it to upgrade the chart or after a manual change |
| `make preseed` | Trigger the latency-bound items before a talk |
| `make hooks` | Install the local gitleaks pre-commit hook |
| `make plant-secret` | Plant a FAKE secret so the next commit is blocked (Layer 0 beat) |
| `make lab-stop` | Park the lab now: AKS deallocated + LB/service IPs dropped (egress IP kept), Container App to 0 |
| `make lab-start` | On-demand start: AKS + Container App, **waits until ready** and prints the control-panel URL |
| `make disable-plans` | Revert Defender plans to Free (stops billing) |
| `make destroy` | Delete the resource group (prompts first) |

## Deploy

```bash
# 1. Edit infra/main.bicepparam (see the toggles below).
# 2. Deploy everything (subscription scope: RG + workload + Defender plans).
az login
az account set --subscription <your-sub-id>
make deploy          # or: bash scripts/deploy.sh
```

**Deploy toggles** (`infra/main.bicepparam`):

| Parameter | Default | What it does |
| --- | --- | --- |
| `namePrefix` / `location` | `defdemo` / `swedencentral` | Resource naming and region (see [Region choice](#region-choice-swedencentral)) |
| `aksNodeVmSize` | `Standard_D2ds_v5` | Smallest node with an ephemeral OS disk; fallback SKU in `docs/architecture.md` |
| `deployFoundry` | `false` | **Optional.** Foundry account + `gpt-4o-mini`. When true the control panel gains a prompt window for direct model inference (what Defender for AI Services protects). Off by default: the panel's main job is the cluster |
| `kubectlMode` | `demo` | Control-panel console: `readonly` (get/describe/logs), `demo` (adds the scripted simulations), `unrestricted` (arbitrary exec, lab only) |
| `enableDefenderPlans` | `true` | Enables CSPM, Containers, AI and Storage plans at subscription scope; `false` if a policy already manages them |
| `defenderSensorViaHelm` | `true` | Helm sensor (default): the cluster is tagged `ms_defender_container_exclude_sensors=true`, the add-on is off, and `deploy.sh` installs the chart. Needed for a working image gate in swedencentral, plus drift **blocking**. `DEFENDER_SENSOR_VIA_HELM=false` falls back to the add-on |
| `deployFlux` | `true` | Flux GitOps syncing shared resources plus separate blocked/allowed workload Kustomizations; set `DEPLOY_FLUX=false` for local bootstrap |
| `acaLocation` / `acaEnvironmentName` | `swedencentral` / `defdemo-aca-env` | ACA location/name, independent from AKS and other core resources |
| `adminPrincipalId` | from env | User object ID for AKS admin and optional Foundry access. Local deployment derives it from the signed-in user; `deploy-lab` accepts the ID or a UPN such as `john.doe@contoso.com` |

Recommended first run: leave Foundry off and Flux on. Private repositories require a read-only
fine-grained PAT in `FLUX_GITHUB_TOKEN` (secret in Actions; environment variable locally).
Never commit it or place it in `main.bicepparam`. Use `DEPLOY_FLUX=false` only when Flux cannot
reach the repository; deployment then applies the same kustomization locally.

`make deploy` treats ARM success as only one checkpoint. It also builds/pushes the real
control-panel images, grants the panel its namespace-scoped AKS role, reconciles Azure Policy
to `DEPLOY_AZURE_POLICY`, and runs `make verify-deployment`. Generated Basic/API credentials
are reused from the ignored mode-0600 `.deploy-secrets.env` file on later retries.

### ACA regional fallback

ACA capacity is allocated at deployment time and has no reliable preflight API. If the
primary deployment returns `ManagedEnvironmentNoAvailableCapacityInRegion`, `deploy.sh`
deploys only ACA in `ACA_FALLBACK_LOCATION` (Norway East by default) under a different name.
AKS and other core resources are not redeployed.

```bash
ACA_LOCATION=swedencentral \
ACA_ENV_NAME=defdemo-aca-env-sec \
ACA_FALLBACK_LOCATION=norwayeast \
ACA_FALLBACK_ENV_NAME=defdemo-aca-env-noe \
make deploy
```

The fallback is deliberately limited to the capacity error. Authentication, validation,
quota and permission failures stop immediately. `make deploy-aca` exposes the same targeted
ACA workflow for later updates.

After deployment: run `make gating`, configure GitHub and its Defender connector, confirm
`make flux-status`, and run `make preseed` two to three days before a talk. Basic auth is ready
immediately; set `PANEL_ENTRA_USER` and run `make auth` for single-user Entra sign-in. Foundry
and `make foundry-agent` remain optional.

## The control panel

The ACA app shows AKS inventory, logs, a constrained kubectl console, alert simulations, and
optional Foundry chat. Its user-assigned identity calls the Entra-enabled AKS API directly—no
kubeconfig, client secret, or cluster-admin credential. Structured views use cluster Reader;
console commands exec into the unexposed `demo-ops/kubectl-runner`, with Azure RBAC and
Kubernetes RBAC limiting writes to demo namespaces. Calls are audited in `CloudAuditEvents`.

The scenario picker creates short-lived `mdc-alert-triage` Jobs in `demo-ops`. Scenarios are
benign; the privileged variant requires `kubectlMode=unrestricted`.

**Signing in to the panel.** The panel is a remote shell into your cluster, so it is **never deployed open**. You only choose *how* it is protected, and the deployment picks the mode for you:

| You set | Mode | What happens |
| --- | --- | --- |
| nothing | **basic** | A generated password is stored as Container App secret `panel-basic-password` and printed once. |
| `PANEL_ENTRA_USER=<upn>` | **entra** | `make auth` enables EasyAuth and assigns only that user. |

```bash
make deploy                                            # basic auth, random password printed once
PANEL_ENTRA_USER=you@tenant.com make deploy && make auth   # Entra, scoped to you only
```

Entra mode is single-tenant and sets `appRoleAssignmentRequired`; basic mode is a lab fallback
without MFA. Only `/healthz` is anonymous. The panel always calls AKS as its own identity, not
on behalf of the signed-in user. `kubectlMode` defaults to `demo`; use `readonly` for observation
or `unrestricted` only in an isolated lab.

## Layer 0: the hook you cannot rely on

```bash
make hooks          # install the hook (once per clone, per developer)
make plant-secret   # write a FAKE credential to app/aks-webapp/config/demo.env
git add app/aks-webapp/config/demo.env
git commit -m "add app config"               # BLOCKED by gitleaks
git commit -m "add app config" --no-verify   # goes straight through
```

The fake secret is generated at demo time and never committed. The hook scans staged changes,
not existing history.

**Every one of these defeats it, and none of them requires special privileges.**

| Bypass | Why it works |
| --- | --- |
| Never run `make hooks` | Git does not distribute hooks on clone |
| `git commit --no-verify` | Skips every pre-commit hook. One flag |
| `SKIP=gitleaks git commit` | The pre-commit framework's own opt-out |
| `pre-commit uninstall` or `rm .git/hooks/pre-commit` | The developer owns the file |
| `git config core.hooksPath /dev/null` | Points git at a different hooks directory |
| Commit from the GitHub web UI, the API, or another client | Never touches the local machine |

Treat the hook as convenience. GitHub push protection, required checks, and Defender agentless
scanning provide the server-side controls the developer cannot locally disable.

## Container Apps egress lockdown (optional)

By default ACA uses Microsoft-managed networking, so there is no customer subnet or NSG.

Opt in to restrict where the panel may call out to:

```bash
ENABLE_ACA_VNET=true make deploy                          # deny-all egress + allow list
ENABLE_ACA_VNET=true AKS_API_SERVER_IP=<ip> make deploy   # and pin the API server rule
```

This creates a VNet with deny-all outbound plus required Azure, ACR, DNS, AKS API, monitoring,
and optional Foundry allowances. Before enabling it:

- **It costs about $26 a month.** A managed load balancer and two standard public IPs are
  created in an `ME_*` resource group. They belong to the environment rather than the app, so
  `make park` does not stop the meter.
- **It cannot be switched on an existing lab.** An environment's network type is fixed when it
  is created, so flipping the flag means deleting the environment. The panel gets a new
  hostname and `make auth` has to be re-run.
- **It controls egress only.** On an internet-facing environment, inbound traffic reaches the
  platform's public IP without traversing your subnet, so authentication remains the access
  control for the panel.

The AKS API has no dedicated NSG service tag: use the broad regional `AzureCloud` tag or pin an
IP that can change after stop/start. See [ACA-readme.md](ACA-readme.md) for the rule table.

## GitHub setup: OIDC, variables, secrets

Workflows use Azure OIDC, Defender CLI authentication, and GitHub Advanced Security. They do
not store long-lived Azure credentials.

**1. Azure OIDC.** Set client, tenant, and subscription IDs as repository variables. Add a
federated credential for `repo:<org>/<repo>:ref:refs/heads/main`, audience
`api://AzureADTokenExchange`; add the pull-request subject only if required.

- RBAC depends on the workflow. The Flux demo workflows need **AcrPush** on the registry; their GitHub token writes the selected manifest to `main`, then Flux deploys it. They do not call the AKS API. `lab-park` needs AKS control and node-resource-group network permissions plus Container Apps scaling access. `destroy-lab` needs permission to delete the selected resource group. The platform deployment sample needs permissions for its subscription-scope deployment and resource creation; do not assume the demo-only role assignments cover it.

**2. Defender CLI auth.** Used by `security-defender-scan-only` and both `atlas-ci` gates. Either the GitHub connector (preferred, tokenless) or token-based: Defender for Cloud > Environment settings > Integrations > **DevOps Ingestion**, then store the values as secrets. Without them `security-defender-scan-only` skips cleanly.

**3. GitHub Advanced Security.** Enable push protection and secret scanning in repository or
organization settings.

| Kind | Name | Value | Used by |
| --- | --- | --- | --- |
| var | `AZURE_CLIENT_ID` | `<app (client) ID of the OIDC app registration>` | OIDC login in `deploy-lab`, the manual demos, `lab-park`, `destroy-lab`, and platform deployment sample |
| var | `AZURE_TENANT_ID` | `<Entra tenant ID>` | OIDC login |
| var | `AZURE_SUBSCRIPTION_ID` | `<subscription ID>` | OIDC login |
| var | `AZURE_RESOURCE_GROUP` | `<resource group>`, e.g. `rg-defdemo` | `deploy-lab`, `lab-park`, the manual demos, Flux status checker, platform deployment sample |
| var | `AKS_NAME` | `defdemo-aks` | `lab-park`, the manual demos, Flux status checker |
| var | `ACR_LOGIN_SERVER` | `<acr>.azurecr.io` | Manual demo image references. Changes with every new lab: copy it from the `deploy-lab` run summary |
| var | `ACR_NAME` | `<acr>` | Push by both unscanned demos and after a successful Defender scan |
| var | `APP_NAME` | `defdemo-app` (optional, this is the default) | `lab-park` Container App target |
| var | `AZURE_LOCATION` | `swedencentral` | Platform deployment sample region |
| secret | `DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET` | Replace with the dedicated Defender CLI identity | Defender CLI in `security-defender-scan-only` and the pipeline-scan demo |
| secret | `FLUX_GITHUB_TOKEN` | `<fine-grained PAT, read-only Contents on this repo>` | Flux Git access for a private repository (`deploy-lab`, `update-flux-auth`) |
| var | `COPILOT_FOUNDRY_ENDPOINT` | `https://<foundry-account>.openai.azure.com` | Copilot triage and the CI failure digest: your model (BYOK) |
| var | `COPILOT_FOUNDRY_DEPLOYMENT` | `<model deployment>`, e.g. `gpt-5.4-mini` | Copilot triage and the CI failure digest |
| var | `COPILOT_WIRE_API` | `responses` for GPT-5 deployments (empty = chat completions) | Copilot triage and the CI failure digest |
| secret | `COPILOT_FOUNDRY_API_KEY` | `<Foundry key>` (optional; empty = Entra ID via the OIDC login) | Copilot triage and the CI failure digest |

Tenant/subscription IDs are identifiers; federation and RBAC control access. Set all three
Defender secrets before running its workflows. These long-lived credentials are
only for the intentionally weak Ship-It sample in a separate repository:

| Kind | Name | Used by |
| --- | --- | --- |
| secret | `ACR_ENDPOINT`, `ACR_USERNAME`, `ACR_PASSWORD` | Ship-It sample only: deliberately weak long-lived registry credentials |

### Manual admission-control demo workflows

Three workflows under `.github/workflows/` are manual-only (`workflow_dispatch`):

| Workflow | Pipeline scan | Expected result |
| --- | --- | --- |
| `demo-admission-blocked.yml` | Report only | Validates/builds, runs a Gitleaks secret scan (reports the planted fake secret and continues by default, `skip_secret_findings=true`) and a Defender CLI image scan that lists the CVEs but never blocks, pauses for `showcase` approval, publishes the vulnerable image anyway and waits for admission to block it |
| `demo-admission-allowed.yml` | Report only | Validates/builds, runs a Gitleaks secret scan (reports the planted fake secret and continues by default, `skip_secret_findings=true`) and a Defender CLI image scan that lists the CVEs but never blocks, pauses for `showcase` approval, then publishes the vulnerable image to the namespace outside admission scope |
| `demo-pipeline-scan-blocked.yml` | Defender CLI image scan | The vulnerable image fails before ACR login, push, or GitOps manifest update; if it passes, the workflow waits for the selected Flux Kustomization |

Each workflow pushes a unique tag, changes only its Flux manifest, and waits for reconciliation.
OIDC needs ACR Push and Reader on Flux configuration `demo-apps`; `GITHUB_TOKEN` needs Contents
write. No Kubernetes credentials are used. `NotReady` is success for the blocked demo; `Ready`
is required for allowed. Private repositories also need `FLUX_GITHUB_TOKEN`.

## Exception approvals: public webhook here, OIDC front door in production

The [exception playbook](docs/exception-approval-playbook.md) sends GitHub requests through a
Logic App to Teams and writes decisions back as `risk.acceptance/*` annotations. This lab uses
a public SAS/HMAC endpoint with IP filtering and server-side fact verification. Production
should front it with APIM and GitHub OIDC; the strongest form adds a Logic App Standard private
endpoint and an ephemeral VNet runner.

## GitHub connector (manual, by design)

The GitHub connector requires a manual OAuth consent flow:

- Under **Environment settings → Add environment → GitHub**, authorize the app and select the organization. This enables central code-to-runtime mapping without editing application workflows ([docs](https://learn.microsoft.com/en-us/azure/defender-for-cloud/container-image-mapping)).
- **Connect before you build the hero image.** Images built and deployed *prior* to connecting may have limited mapping support.
- Enable **agentless code scanning** on the connector (Preview). It scans the default branch daily, produces SBOM, and cannot break builds. Seed it 3 days before a talk.
- Enable **pull request annotations** (needs GitHub Advanced Security) if you want inline PR findings.

Atlas uses connector-based Defender CLI authentication; `atlas-ci.yml` retains token auth as a
fallback. Both require Defender CSPM.

## AKS sizing

Smallest practical node SKU that supports an ephemeral (non-persistent) OS disk and still runs the Defender sensor: `Standard_D2ds_v5`. The lab uses 2 nodes by default, `osDiskType: Ephemeral`, Cilium network policy, and OIDC + workload identity. Details and the fallback SKU are in `docs/architecture.md`.

## Region choice: `swedencentral`

`swedencentral` supports the lab's agentless code-scanning connector and optional
`gpt-4o-mini` deployment. Verified against Microsoft Learn on 2026-09-18.

| Region | Agentless code scanning region list | Foundry `gpt-4o-mini` | Verdict |
| --- | --- | --- | --- |
| Norway East | not listed | almost no regional-Standard models (one `gpt-4o` version) | two strikes, rejected |
| Poland Central / Spain Central | not listed | available | quiet, but fails the scanning list |
| West Europe / North Europe | listed | available (West Europe weaker under regional Standard) | works, but the most crowded |

Only the Defender GitHub connector has the scanning-region constraint; AKS and ACA may run
elsewhere while the connector remains in a supported region.

## What is not in Bicep, and why

- **Gated deployment rules and binary drift policy** have no ARM resource type yet. Portal or REST, see `infra/postdeploy/`.
- **GitHub connector** is an OAuth consent flow, manual.
- **Foundry agent create + publish + tool binding** goes through the SDK / `azd ai`, see `infra/postdeploy/`.
- **gitleaks pre-commit hook, the atlas-ci/shipit workflows, branch protection, and GitHub Advanced Security** live in the sample repos / GitHub settings.

## Cost and teardown

The lab enables paid Defender plans and Azure compute. `lab-park` stops AKS, removes ephemeral
LoadBalancer resources, preserves the managed egress IP, and scales ACA to zero. `make lab-start`
restarts and verifies them; public service IPs may change. Its OIDC identity needs Network
Contributor on the AKS node resource group. ACR, Foundry, and Defender plans remain billable.

```bash
make destroy          # deletes the resource group (prompts for the RG name first)
make disable-plans    # reverts the subscription-scope Defender plans to Free
```

The `destroy-lab` workflow provides the same guarded deletion. Defender plans are subscription
scoped; only `make disable-plans` reverts them to Free.

## Safety notes

- The Container App can run actions against AKS. Keep basic auth or Entra EasyAuth enabled and retain its least-privilege cluster Reader plus demo-namespace Writer scopes.
- The sample app and Dockerfile are intentionally vulnerable. Do not reuse them for anything real.
- Simulations are inert stubs in the scaffold. Wire them to the demo namespace only.
