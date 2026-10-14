using 'main.bicep'

// ---- Edit these ----
// REGION: swedencentral is the one region that satisfies every feature this lab uses
// in a single region (verified 2026-09-18):
//   1. Defender agentless code scanning (Preview) supported regions: Australia East,
//      Canada Central, Central US, East Asia, East US, North Europe, Sweden Central,
//      UK South, West Europe. Norway East, Poland Central, Spain Central are NOT listed.
//   2. Foundry: gpt-4o-mini 2024-07-18 is available in Sweden Central under every
//      deployment type. Norway East has almost no regional-Standard models.
//   3. swedencentral is large, modern and less congested than westeurope/northeurope.
// If you must use another region, keep the GitHub connector in a listed region and
// confirm the model in Foundry's region table before deploying.
param location = 'swedencentral'
// Keep the core lab in Sweden Central while allowing ACA to use another region when
// regional managed-environment capacity is unavailable.
param acaLocation = readEnvironmentVariable('ACA_LOCATION', 'swedencentral')
param namePrefix = 'defdemo'
param acaEnvironmentName = readEnvironmentVariable('ACA_ENV_NAME', 'defdemo-aca-env')

// Resource group. Every script in this repo reads the same RG variable, so one
// export drives deploy, park/start, auth and destroy:  RG=<name> make deploy
param resourceGroupName = readEnvironmentVariable('RG', 'rg-defdemo')

// Your object ID for playground + data-plane roles. deploy.sh sets ADMIN_PRINCIPAL_ID
// from the signed-in user; falls back to empty if unset.
param adminPrincipalId = readEnvironmentVariable('ADMIN_PRINCIPAL_ID', '')

// Smallest node that supports an ephemeral OS disk. Fallback: 'Standard_D2s_v3'
// (pins ephemeral OS to the smaller cache disk; see docs/architecture.md).
param aksNodeVmSize = 'Standard_D2ds_v5'

// Two nodes. One Standard_D2ds_v5 has 1900m allocatable CPU and the platform pods already
// request ~1830m, so the Defender admission controller (600m) and the sensor DaemonSet stay
// Pending on a single-node cluster and security gating never actually enforces.
param aksNodeCount = 2

// Container Insights (ama-logs). OFF: it costs an extra DaemonSet pod per node plus a
// replicaset pod (~300m CPU of requests) and Defender's telemetry never goes through it.
// Set true only when you want kubectl-free log browsing in the portal.
param deployContainerInsights = bool(readEnvironmentVariable('DEPLOY_CONTAINER_INSIGHTS', 'false'))

// Azure Disk/File CSI drivers + snapshot controller. OFF: no PersistentVolumeClaim exists in
// this lab and every pod volume is hostPath/projected/configMap/secret/emptyDir, so the
// drivers add four DaemonSet pods and nothing else. Set true before any workload needs a PVC.
param deployCsiDrivers = bool(readEnvironmentVariable('DEPLOY_CSI_DRIVERS', 'false'))

// Azure Policy for Kubernetes (gatekeeper). OFF: three gatekeeper pods plus two azure-policy
// pods, ~300m CPU of requests, and nothing in this demo reads them - Defender's
// misconfiguration enforcement arrives as ValidatingAdmissionPolicies from the Helm sensor.
// Watch it: enabling the Defender for Containers plan can turn this add-on back on by itself.
param deployAzurePolicy = bool(readEnvironmentVariable('DEPLOY_AZURE_POLICY', 'false'))

// Foundry model-inference demo (Defender for AI Services). Set false to skip cost.
// Foundry is OPTIONAL. The Container App's main job is the AKS control panel; the AI chat is
// an extra feature that only appears when this is true. Leave false to skip the cost/quota.
param deployFoundry = false
param aiModelName = 'gpt-4o-mini'
param aiModelVersion = '2024-07-18'

// Turn on Defender plans. Set false if an org policy already manages pricings.
param enableDefenderPlans = true

// Defender sensor via Helm instead of the AKS add-on. DEFAULT TRUE. The cluster is created with
// the ms_defender_container_exclude_sensors tag (so auto-provisioning never adds the add-on next
// to it) and the add-on disabled; deploy.sh then installs the chart. Why Helm: the add-on's image
// gate needs securityGating.identities, which swedencentral rejects, so it fails OPEN. The Helm
// admission controller reads ACR as the kubelet identity (IMDS) and needs no such field. Helm
// also brings drift BLOCKING and antimalware. Set false only to fall back to the add-on.
param defenderSensorViaHelm = bool(readEnvironmentVariable('DEFENDER_SENSOR_VIA_HELM', 'true'))
// Gated deployment step 4 (securityGating.identities) in the cluster body. Off: the resource provider
// rejected the field in swedencentral, so infra/postdeploy/attach-gating-identity.sh does it after deploy.
param attachGatingIdentities = bool(readEnvironmentVariable('ATTACH_GATING_IDENTITIES', 'false'))

// Namespace of the Defender admission-controller ServiceAccount. Empty = derived (mdc with
// Helm, kube-system with the add-on). The gating federated credential subject follows it.
param defenderSensorNamespace = readEnvironmentVariable('DEFENDER_NAMESPACE', '')

// GitOps with Flux (AKS extension). ON by default: Flux bootstraps all namespaces,
// the kubectl runner, and the demo workloads from app/k8s. For a private repo, set the
// GitHub Actions secret FLUX_GITHUB_TOKEN (or export it locally); deploy.sh passes it to
// Flux as a protected setting. Set DEPLOY_FLUX=false only when Flux cannot reach the repo.
// FLUX_SEPARATE_DEPLOYMENT=true (set by deploy.sh) leaves Flux out of this deployment: deploy.sh
// deploys infra/modules/flux.bicep on its own, in parallel with the post-deploy steps, so the
// ~6 min Flux extension install no longer blocks them.
param deployFlux = bool(readEnvironmentVariable('DEPLOY_FLUX', 'true')) && !bool(readEnvironmentVariable('FLUX_SEPARATE_DEPLOYMENT', 'false'))
param gitRepoUrl = readEnvironmentVariable('GIT_REPO_URL', '')
param gitRepoToken = readEnvironmentVariable('FLUX_GITHUB_TOKEN', '')
param gitBranch = 'main'

// Security findings (gated-deployment prerequisite). ON: the extension name is undocumented
// but accepted by the pricings API (confirmed in a live tenant). If a deployment ever fails on
// it, set false and toggle it in the portal. Verify with: make verify-gating
param enableSecurityFindingsExtension = true

// WHO MAY OPEN THE CONTROL PANEL. The panel is a remote shell into the cluster, so it is
// never left open; you only choose HOW it is protected.
//   set PANEL_ENTRA_USER=<upn>  -> Entra EasyAuth, scoped to THAT USER ONLY (make auth)
//   leave it empty              -> the app enforces HTTP Basic with a RANDOM password that
//                                  deploy.sh generates and prints once
param panelEntraUser = readEnvironmentVariable('PANEL_ENTRA_USER', '')
param panelBasicPassword = readEnvironmentVariable('PANEL_BASIC_PASSWORD', '')
param panelBasicUser = readEnvironmentVariable('PANEL_BASIC_USER', 'panel')

// Machine access to the REST API: X-API-Key on /api/* only, never on the HTML console.
// deploy.sh generates a key when PANEL_API_KEY is empty and prints it once.
param panelApiKey = readEnvironmentVariable('PANEL_API_KEY', '')

// Control-panel image. Empty = a healthy port-80 quickstart placeholder. deploy.sh builds
// the real image and build-push-app.sh switches ingress to 8080 before installing it.
param appImage = readEnvironmentVariable('APP_IMAGE', '')

// ---- ACA egress lockdown (OPT-IN, default OFF) ----------------------------
// false = the Container Apps environment runs on the platform-managed network. There is no
//         subnet in your subscription, so no network security group is possible. No extra cost.
// true  = the environment joins a VNet whose subnet carries a deny-all egress NSG with
//         allow rules only for Entra, ACR, Microsoft Artifact Registry, Azure Monitor, Azure
//         DNS, the AKS API server and (if deployFoundry) Azure AI Services.
//
// COSTS ~$26/MONTH: a managed load balancer plus two standard public IPs are created in an
// ME_* resource group. These belong to the ENVIRONMENT, not the app, so `make park` does NOT
// stop the meter. Full write-up, including the AKS API server caveat: ACA-readme.md
//
// NOT CHANGEABLE IN PLACE: an environment's network type is fixed at creation. Flipping this
// on an existing lab means deleting the environment, which gives the panel a new hostname and
// requires re-running `make auth`.
param enableAcaVnet = bool(readEnvironmentVariable('ENABLE_ACA_VNET', 'false'))
param acaVnetAddressPrefix = '10.60.0.0/16'
param acaSubnetPrefix = '10.60.0.0/26'

// Pin the egress rule to the AKS API server IP instead of the regional AzureCloud tag.
// The IP can change across a cluster stop/start, so re-check it after `make start`:
//   dig +short $(az aks show -g <rg> -n <aks> --query fqdn -o tsv) | tail -1
param aksApiServerIp = readEnvironmentVariable('AKS_API_SERVER_IP', '')
