# Defender for Cloud demo lab - single front door.
# Run `make` or `make help` to see targets. Recipes use `>` (not tab) via RECIPEPREFIX.
.RECIPEPREFIX = >
SHELL := /usr/bin/env bash

NAME_PREFIX ?= defdemo
LOCATION    ?= swedencentral
RG          ?= rg-$(NAME_PREFIX)
export RG
export NAME_PREFIX
export LOCATION
DEPLOY_FLUX ?= true
export DEPLOY_FLUX

.PHONY: help
help: ## Show this help
> @grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

.PHONY: validate
validate: test ## Compile all Bicep + run the static app checks (no Azure login needed)
> az bicep build --file infra/main.bicep --stdout > /dev/null
> az bicep build --file infra/aca.bicep --stdout > /dev/null
> @for f in scripts/deploy.sh scripts/deploy-aca.sh scripts/bootstrap-cluster.sh scripts/verify-deployment.sh infra/postdeploy/reconcile-azure-policy.sh infra/postdeploy/configure-sensitive-storage.sh scripts/build-push-app.sh; do bash -n "$$f"; done
> @echo "bicep + shell syntax OK"

.PHONY: test
test: ## Static checks: control-panel integrity + docs in sync (plain python3, no deps)
> python3 tests/test_app_integrity.py
> python3 tests/test_docs_in_sync.py

.PHONY: whatif
whatif: ## Preview infra changes against the subscription
> az deployment sub what-if --location $(LOCATION) --template-file infra/main.bicep --parameters infra/main.bicepparam

.PHONY: prereqs
prereqs: ## Install the Bicep CLI + required az extensions (containerapp, k8s-configuration) + register providers
> bash scripts/az-prereqs.sh

.PHONY: deploy
deploy: ## Deploy infra: RG + workload + Defender plans (runs prereqs first)
> bash scripts/deploy.sh

.PHONY: deploy-aca
deploy-aca: ## Deploy only ACA; falls back from ACA_LOCATION to ACA_FALLBACK_LOCATION
> bash scripts/deploy-aca.sh

.PHONY: bootstrap
bootstrap: ## Bootstrap AKS manifests when Flux is disabled
> bash scripts/bootstrap-cluster.sh

.PHONY: verify-deployment
verify-deployment: ## End-to-end verification of AKS, Flux/runner, roles, ACA health and policy state
> bash scripts/verify-deployment.sh

.PHONY: app
app: ## Build + push the vulnerable app, point the Container App at it
> bash scripts/build-push-app.sh

.PHONY: auth
auth: ## Entra sign-in for the panel, scoped to ONE user: PANEL_ENTRA_USER=<upn> make auth (no user = basic auth already active)
> bash infra/postdeploy/enable-aca-auth.sh

.PHONY: grant-panel
grant-panel: ## Grant the control panel exec rights in demo-ops (namespace-scoped AKS RBAC Writer)
> bash infra/postdeploy/grant-controlpanel-access.sh

.PHONY: heartbeat
heartbeat: ## Re-point the x-mdc-allowed heartbeat at the panel FQDN via the Flux configuration (normally automatic)
> bash infra/postdeploy/configure-heartbeat.sh

.PHONY: sensitive-storage
sensitive-storage: ## Seed fake sensitive Blob data and configure the AKS web app workload identity
> bash infra/postdeploy/configure-sensitive-storage.sh

.PHONY: gating
gating: ## Configure gated-deployment rule + binary drift policy (portal/REST helper)
> bash infra/postdeploy/configure-gating-and-drift.sh

.PHONY: foundry-agent
foundry-agent: ## Publish the Foundry agent for chat mode B (needs Agent 365)
> bash infra/postdeploy/foundry-agent.sh

.PHONY: verify-gating
verify-gating: ## Check the FOUR gated-deployment prerequisites and say what is missing
> bash infra/postdeploy/verify-gating-prereqs.sh

.PHONY: gating-identity
gating-identity: ## Attach the gating identity to securityGating.identities (add-on gating fails OPEN without it)
> bash infra/postdeploy/attach-gating-identity.sh

.PHONY: sensor-helm
sensor-helm: ## Install the Defender sensor via Helm (drift BLOCKING). Needs defenderSensorViaHelm=true at deploy
> bash infra/postdeploy/install-defender-helm.sh

.PHONY: flux-status
flux-status: ## Show Flux GitOps compliance state + Kustomization (GitOps denied-by-gate step)
> az k8s-configuration flux show -g $(RG) -c $(NAME_PREFIX)-aks -n demo-apps -t managedClusters -o table || true
> kubectl get gitrepositories,kustomizations -A 2>/dev/null || echo "(run: az aks get-credentials -g $(RG) -n $(NAME_PREFIX)-aks)"

.PHONY: connect-github
connect-github: ## Print the manual GitHub connector runbook
> @cat infra/postdeploy/connect-github.md

.PHONY: preseed
preseed: ## Trigger the latency-bound items before a talk
> bash scripts/preseed.sh

.PHONY: hooks
hooks: ## Install the local gitleaks pre-commit hook (Layer 0)
> pre-commit install

.PHONY: plant-secret
plant-secret: ## Layer 0 beat: plant a FAKE secret so the next `git add` + commit is blocked
> bash scripts/plant-secret.sh

.PHONY: approval-gate
approval-gate: ## Make `showcase` a real approval gate (required reviewers); needs a public repo
> bash scripts/setup-approval-gate.sh

.PHONY: lab-stop
lab-stop: ## Park the lab now: AKS deallocate + drop LB/service IPs (keep egress IP), Container App to 0 (nightly via lab-park)
> bash scripts/lab-park.sh stop

.PHONY: lab-start
lab-start: ## On-demand start: AKS + Container App, waits until ready, prints the URL
> bash scripts/lab-start.sh

.PHONY: disable-plans
disable-plans: ## Revert Defender plans to Free (stops billing, keeps resources)
> bash infra/postdeploy/disable-defender-plans.sh

.PHONY: destroy
destroy: ## Delete the resource group (prompts first)
> bash scripts/destroy.sh
