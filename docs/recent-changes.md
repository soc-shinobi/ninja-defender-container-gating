# Recent changes (October 2026): what changed, and what to check when something breaks

A troubleshooting index for the changes of 10-11 October 2026. Each entry: what changed, where,
and the symptom it would cause if something is off. Lab-specific values (IDs, resource group,
ACR, Foundry account) are in `.private/lab-values.md`, which is not in Git.

## 1. Repository cleanup

**What changed**

- Moved out of Git into `.private/` (still on disk, ignored via `.gitignore`):
  - `.github/other-samples/` (10 workflow/config samples from other projects) to
    `.private/github-other-samples/`
  - `workbooks/sample-workbook.json` (unrelated "Agentic AI Security" workbook) to
    `.private/workbooks/`
- `README.md` variables table: real values replaced by placeholders; the real ones are in
  `.private/lab-values.md`. Rows added for `FLUX_GITHUB_TOKEN` and the Copilot / Foundry
  settings.
- Workflow fallback resource group (the lab's own name) changed to `rg-defdemo` (all workflows
  and `.github/workflows-samples/platform-deploy.yml`). `destroy-lab` now suggests `rg-defdemo`.
- Two personal comments reworded (`destroy-lab.yml`, `lab-park.yml`); `connect-github.md` now
  links `atlas-ci.yml` (the old `atlas-build.yml` never existed).

Not touched: Bicep, Kubernetes manifests, apps, scripts, Makefile targets.

**If something breaks**

| Symptom | Likely cause | Fix |
|---|---|---|
| A workflow targets `rg-defdemo` / "resource group not found" | Repo variable `AZURE_RESOURCE_GROUP` is empty or was deleted, so the new fallback applies | Set the variable again (`gh variable set AZURE_RESOURCE_GROUP --body <rg>`) |
| `destroy-lab` deletes nothing / wrong group | It only uses the typed input, which now defaults to `rg-defdemo` | Type the real resource group when running it |
| `make deploy` builds a second lab in `rg-defdemo` | Local runs fall back to `rg-${NAME_PREFIX}` (unchanged, but easy to forget) | `RG=<your rg> make deploy` |
| A sample you need is gone | It was moved, not deleted | Copy it back from `.private/` |

## 2. Namespaces renamed: `mdc-allowed` / `mdc-blocked` to `x-mdc-allowed` / `x-mdc-blocked`

**What changed:** every manifest, the Flux paths (`app/k8s/x-mdc-*`, `infra/modules/flux.bicep`),
the runner RBAC, the workload identity credential (`aks-webapp-x-mdc-allowed`), the panel, the
demo workflows, the docs and tests.

**Things that live outside Git and had to follow by hand**

- Defender portal rules are matched by namespace name: gating rule (`x-mdc-blocked`),
  misconfiguration policies, both drift rules. If the vulnerable app is **admitted** in
  `x-mdc-blocked`, or no drift / misconfiguration alert fires, check their scopes first.
- `aks-webapp` service account, `sensitive-storage` and `panel-heartbeat` ConfigMaps in
  `x-mdc-allowed` are created by `deploy.sh` post-deploy scripts, not by Flux. If the webapp
  pod is stuck with `serviceaccount "aks-webapp" not found`, run `deploy-lab`, or
  `infra/postdeploy/configure-sensitive-storage.sh` and `configure-heartbeat.sh`.
- The old credential `aks-webapp-mdc-allowed` on `defdemo-aks-webapp-id` is unused and can be
  deleted.

| Symptom | Fix |
|---|---|
| Flux: `kustomization path not found: .../app/k8s/mdc-allowed` | Flux config still has old paths: run `deploy-lab` (old events stay visible for about an hour) |
| Webapp: `[blob] ERROR` / token exchange failure | Credential for `system:serviceaccount:x-mdc-allowed:aks-webapp` missing: run `deploy-lab` |
| Panel button returns `Forbidden` on `mdc-*` | Browser tab loaded before the panel update: reload |

## 3. `deploy.sh` stops early on a stopped or busy AKS cluster

Before the deployment starts, `scripts/deploy.sh` now checks the cluster: not `Running` ends
with "Start it first: ... make lab-start"; an operation in progress (`Starting`, `Updating`, ...)
ends with an `az aks wait` hint; `Failed` continues with a warning. A first deploy (no cluster
yet) is unaffected. If a deploy stops here, it is the cluster state, not the template.

## 4. Approval gate (`showcase` environment)

`scripts/record-approval.sh` runs in the `approval` job of `aca-webapp` and the three
`demo-*` workflows. On this private repo there are no required reviewers, so the job passes
and the summary says **"Showcase approval not enforced"**; that is expected. After making the
repository public, run `make approval-gate` (`scripts/setup-approval-gate.sh`) and the same
jobs wait for a reviewer. If the job fails with a permission error, it needs `actions: read`.

## 5. Copilot on your own model (BYOK)

Repo variables `COPILOT_FOUNDRY_ENDPOINT`, `COPILOT_FOUNDRY_DEPLOYMENT`, `COPILOT_WIRE_API`
and secret `COPILOT_FOUNDRY_API_KEY` point Copilot CLI at the Foundry deployment. The API key
wins; delete the secret to fall back to Entra ID (the OIDC identity holds Cognitive Services
OpenAI User on the account).

| Symptom | Fix |
|---|---|
| Triage / digest: 401 or "PermissionDenied" | Key rotated: re-set the secret from `az cognitiveservices account keys list` |
| Works with the key, fails without it | Role assignment missing or still propagating |
| "the agent did not write issue.md" | Model throttled or wrong wire API: GPT-5 deployments need `COPILOT_WIRE_API=responses` |

## 6. CI failure digest (`ci-failure-digest.yml`)

Daily at 05:17 UTC. One `ci-failure` issue per workflow whose latest run still fails; issues
close by themselves once the workflow is green. Gate blocks that are the control working
(Gitleaks secret gate, Defender image gate) are listed as "blocked by design" and never open
an issue; the patterns are in `.github/copilot/expected-failures.json`. Try it with
`gh workflow run ci-failure-digest.yml -f dry_run=true` (no model call, no issue changes).

If a deliberate demo failure keeps opening an issue, add its error annotation to
`expected-failures.json`. If a real failure is classed as "by design", the pattern is too broad.

## 7. Security scanning workflows

- `security-defender-scan-only.yml`: the `scan fs` job was removed. Defender CLI `scan fs` is not in the
  CLI reference and on Linux runners it either finds "no applicable tools" or starts the
  Windows builds of its scanners; it never scanned anything. The model scan runs on manual
  dispatch only and uses the documented `--modelscanner-Output`.
- `deploy-lab.yml`: the report-only Bicep scan that used `scan fs` was removed for the same
  reason.
- `aca-webapp.yml`: Gitleaks stays the secret gate; a report-only `defender scan sbom` runs
  next to the anchore SBOM.

## 8. Control panel (`app/webapp`) and the webapp image

- Console: YAML / JSON / describe / table formatting, own colours per theme (light mode was
  unreadable before), a `column -t` pipe filter, and a copy button for the output.
- Top bar: collapse all / expand all. Blades: **✕ close** now ends full-page mode (it used to
  hide the blade and leave the page locked).
- Isolation drill: live TCP connections, crypto-mining trigger (`poolmining.org`), and
  **🔒 restricted pods** (pods labelled `mdc-deny-all-network` or
  `mdc-block-sensitive-interfaces` by a Defender response action).
- `app/aks-webapp/Dockerfile` installs `curl` from `archive.debian.org` (Debian 11 is EOL and
  `deb.debian.org` returns 404 for its security updates). More CVEs in that image is expected.
- Full list of panel commands: `docs/kubectl-command-library.md`.

Panel changes need an `aca-webapp` run; image changes need a rebuild through the demo
workflows before Flux picks them up.
