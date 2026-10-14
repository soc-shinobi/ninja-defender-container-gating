// =============================================================================
// Defender for Cloud code-to-runtime demo lab - main template
// Scope: subscription. Creates the resource group, then the workload plane,
// then turns on the Defender plans that make the demo work.
//
// Focus: container + CI/CD security, shift-left plus defense in depth.
// No WAF / App Gateway / ingress edge security by design.
//
// Verified against Microsoft Learn 2026-09-18. See docs/architecture.md.
// =============================================================================

targetScope = 'subscription'

@description('Location for all resources.')
param location string = 'swedencentral'

@description('Location for Azure Container Apps resources. Defaults to the main resource location.')
param acaLocation string = location

@description('Name of the Azure Container Apps managed environment.')
param acaEnvironmentName string = '${namePrefix}-aca-env'

@description('Short name stem used to build resource names. Lowercase letters and numbers.')
@minLength(3)
@maxLength(12)
param namePrefix string = 'defdemo'

@description('Resource group name.')
param resourceGroupName string = 'rg-${namePrefix}'

@description('Object ID of the user/group that should get admin data-plane roles (you). Leave empty to skip.')
param adminPrincipalId string = ''

@description('AKS node VM size. Must support an ephemeral OS disk. See docs/architecture.md for sizing.')
param aksNodeVmSize string = 'Standard_D2ds_v5'

@description('Azure Policy for Kubernetes (gatekeeper add-on). Off by default: five pods this demo does not use, since Defender ships its misconfiguration rules as ValidatingAdmissionPolicies.')
param deployAzurePolicy bool = false

@description('Azure Disk/File CSI drivers and snapshot controller on the cluster. Off by default: the lab has no PersistentVolumeClaim, so they only add four DaemonSet pods.')
param deployCsiDrivers bool = false

@description('Container Insights add-on (ama-logs) on the cluster. Off by default: ~300m CPU of requests that Defender does not need.')
param deployContainerInsights bool = false

@description('AKS system node count. Default 2 because the Defender admission controller (600m CPU) and sensor do not fit next to the platform pods on one Standard_D2ds_v5.')
param aksNodeCount int = 2

@description('Deploy the Foundry (AI Services) account + model deployment. Costs apply.')
param deployFoundry bool = true

@description('Model to deploy for the AI-call demo (Defender for AI Services covers this).')
param aiModelName string = 'gpt-4o-mini'
param aiModelVersion string = '2024-07-18'

@description('Turn on the Defender for Cloud plans at subscription scope. Set false if a policy already manages them.')
param enableDefenderPlans bool = true

@description('Send securityGating.identities inside the AKS cluster body. Documented from api-version 2025-05-02-preview, but the ContainerService resource provider rejected it in swedencentral on 2026-09-19 (UnmarshalError: unknown field "identities"). Default false: the cluster is created without it and infra/postdeploy/attach-gating-identity.sh attaches the identity afterwards (scripts/deploy.sh runs it). Set ATTACH_GATING_IDENTITIES=true to try it in the cluster body. See infra/modules/aks.bicep.')
param attachGatingIdentities bool = false

@description('Provision the Defender sensor via Helm (drift BLOCKING + antimalware) instead of the AKS add-on. See infra/postdeploy/install-defender-helm.sh.')
param defenderSensorViaHelm bool = true

@description('Send the Security findings component as a pricing extension (gated-deployment prerequisite). ON by default: the name is undocumented but accepted by the pricings API (confirmed in a live tenant). Set false if your tenant rejects it, then toggle in the portal.')
param enableSecurityFindingsExtension bool = true

@description('Deploy Flux (AKS GitOps extension) syncing app/k8s from this repo. Needs gitRepoUrl.')
param deployFlux bool = true
@description('HTTPS URL of this repo (deploy.sh fills it from `git remote origin`).')
param gitRepoUrl string = ''
param gitBranch string = 'main'
@description('Optional GitHub PAT for Flux to clone a private repository. Pass via FLUX_GITHUB_TOKEN; never put it in a parameter file.')
@secure()
param gitRepoToken string = ''

@description('Control-panel kubectl console mode: readonly (get/describe/logs only), demo (adds the scripted simulations), unrestricted (lab only - arbitrary exec).')
@allowed([ 'readonly', 'demo', 'unrestricted' ])
param kubectlMode string = 'demo'

@description('Entra user (UPN or object ID) allowed to open the control panel. EMPTY = the app falls back to HTTP Basic with a random password. Either way the panel is never open.')
param panelEntraUser string = ''
@description('Random basic-auth password (deploy.sh generates one when panelEntraUser is empty).')
@secure()
param panelBasicPassword string = ''

@description('Basic-auth username. Set PANEL_BASIC_USER at deploy time; the app reads it from the BASIC_AUTH_USER environment variable.')
param panelBasicUser string = 'panel'

@description('Namespace of the Defender admission-controller ServiceAccount, used for the gating federated credential. Empty derives it: mdc with the Helm sensor, kube-system with the add-on. Set it explicitly to kube-system for AKS Automatic with Helm.')
param defenderSensorNamespace string = ''

@description('Control-panel image. Empty uses the port-80 quickstart placeholder until scripts/build-push-app.sh switches ingress to 8080 and installs the real image.')
param appImage string = ''

@description('API key for machine access to the REST API (X-API-Key header, /api/* only). deploy.sh generates one when empty.')
@secure()
param panelApiKey string = ''

@description('OPT-IN: put the Container Apps environment in a VNet with an egress-only NSG. Default false. Adds ~$26/month for the managed load balancer and two public IPs, which nightly parking does NOT avoid. Changing this on an existing environment requires recreating it (new hostname, re-run make auth). See ACA-readme.md.')
param enableAcaVnet bool = false
@description('Address space for the lab VNet. Only used when enableAcaVnet is true.')
param acaVnetAddressPrefix string = '10.60.0.0/16'
@description('Subnet for the Container Apps environment. /27 is the documented minimum and subnets cannot be resized afterwards.')
param acaSubnetPrefix string = '10.60.0.0/26'
@description('AKS API server public IP, to pin the egress rule tightly. Empty falls back to the regional AzureCloud tag. The IP can change across a cluster stop/start.')
param aksApiServerIp string = ''

// ---- Resource group -------------------------------------------------------
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

// ---- Workload plane (RG scope) -------------------------------------------
module workload 'modules/workload.bicep' = {
  name: 'workload'
  scope: rg
  // No dependsOn on the Defender plans: the pricings and the workload are independent and
  // deploy in parallel (~2 min saved). The Helm sensor is installed after both have finished.
  params: {
    location: location
    acaLocation: acaLocation
    acaEnvironmentName: acaEnvironmentName
    namePrefix: namePrefix
    adminPrincipalId: adminPrincipalId
    aksNodeVmSize: aksNodeVmSize
    aksNodeCount: aksNodeCount
    deployContainerInsights: deployContainerInsights
    deployCsiDrivers: deployCsiDrivers
    deployAzurePolicy: deployAzurePolicy
    deployFoundry: deployFoundry
    aiModelName: aiModelName
    aiModelVersion: aiModelVersion
    defenderSensorViaHelm: defenderSensorViaHelm
    attachGatingIdentities: attachGatingIdentities
    defenderSensorNamespace: defenderSensorNamespace
    deployFlux: deployFlux
    gitRepoUrl: gitRepoUrl
    gitBranch: gitBranch
    gitRepoToken: gitRepoToken
    kubectlMode: kubectlMode
    panelEntraUser: panelEntraUser
    panelBasicPassword: panelBasicPassword
    panelBasicUser: panelBasicUser
    panelApiKey: panelApiKey
    appImage: appImage
    enableAcaVnet: enableAcaVnet
    acaVnetAddressPrefix: acaVnetAddressPrefix
    acaSubnetPrefix: acaSubnetPrefix
    aksApiServerIp: aksApiServerIp
  }
}

// ---- Defender for Cloud plans (subscription scope) ------------------------
// Deployed BEFORE the workload: security gating on the AKS cluster lists the
// Defender for Containers plan (sensor + gating, registry access + findings) as
// a prerequisite, so the plans must exist when the cluster provisions.
module defender 'modules/defender-plans.bicep' = if (enableDefenderPlans) {
  name: 'defender-plans'
  params: {
    enableSecurityFindingsExtension: enableSecurityFindingsExtension
  }
}

output resourceGroup string = rg.name
output acrLoginServer string = workload.outputs.acrLoginServer
output aksName string = workload.outputs.aksName
output acaAppUrl string = workload.outputs.acaAppUrl
output gatingIdentityClientId string = workload.outputs.gatingIdentityClientId
output foundryEndpoint string = workload.outputs.foundryEndpoint
output panelAuthMode string = empty(panelEntraUser) ? 'basic (random password, see deploy output)' : 'entra (run: make auth)'
output acaNetworkMode string = enableAcaVnet ? 'vnet-integrated (egress NSG active, ~$26/month extra)' : 'platform-managed network (no NSG possible, no extra cost)'
