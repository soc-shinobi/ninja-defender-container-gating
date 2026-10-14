// =============================================================================
// Defender for Cloud plans (subscription scope)
// Turns on exactly the plans the demo needs, with the component extensions.
// Extension names verified from Microsoft.Security/pricings schema 2026-09-18.
//
// NOTE: The AKS-side Defender sensor + security gating is enabled on the
// cluster resource itself (see modules/aks.bicep securityProfile), which is
// the IaC-supported path. These plans light up registry VA, CSPM graph,
// agentless K8s discovery, and AI-call threat protection.
// =============================================================================

targetScope = 'subscription'

@description('Log Analytics workspace resource ID (some components benefit from it).')
param workspaceResourceId string = ''

@description('''Also send the Security findings component as a pricing extension.
GATED DEPLOYMENT PREREQUISITES (docs: enablement-guide-runtime-gated):
  - Defender sensor + Security Gating  -> set on the CLUSTER (modules/aks.bicep securityProfile)
  - Registry access + SECURITY FINDINGS -> the plan, below
"Security findings" generates the signed findings artifact on the image digest, which is the
artifact the admission webhook reads. Without it the gate has nothing to evaluate and every
image looks "unscanned".
Microsoft documents that Security findings CANNOT be enabled through Azure Policy, and the
public pricings schema does not list an extension name for it. ContainerIntegrityContribution
is not in the published schema but IS accepted by the pricings API - confirmed by the lab
author in a live tenant. ON by default for that reason. If a tenant ever rejects the name the
whole pricings deployment fails, so set this false and use `make verify-gating` + the portal
toggle as the fallback.''')
param enableSecurityFindingsExtension bool = true

// ---- Defender CSPM: graph, attack paths, agentless K8s + container VA ------
resource cspm 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'CloudPosture'
  properties: {
    pricingTier: 'Standard'
    extensions: [
      { name: 'AgentlessDiscoveryForKubernetes', isEnabled: 'True' }
      { name: 'ContainerRegistriesVulnerabilityAssessments', isEnabled: 'True' }
      { name: 'AgentlessVmScanning', isEnabled: 'True' }
      { name: 'SensitiveDataDiscovery', isEnabled: 'True' }
      { name: 'EntraPermissionsManagement', isEnabled: 'True' }
    ]
  }
}

// ---- Defender for Containers: registry VA, sensor, gating, runtime --------
// Portal component  ->  extension name here:
//   Registry access                  -> ContainerRegistriesVulnerabilityAssessments  [gating prereq]
//   Kubernetes API access/discovery  -> AgentlessDiscoveryForKubernetes              [gating access pattern]
//   Agentless scanning for machines  -> AgentlessVmScanning   (registry-agnostic runtime VA)
//   Defender sensor                  -> ContainerSensor       [gating prereq; Security Gating
//                                       itself is set per-cluster in modules/aks.bicep]
//   Security findings                -> see enableSecurityFindingsExtension above    [gating prereq]
resource containers 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'Containers'
  dependsOn: [ cspm ]
  properties: {
    pricingTier: 'Standard'
    extensions: union([
      { name: 'ContainerRegistriesVulnerabilityAssessments', isEnabled: 'True' }
      { name: 'AgentlessDiscoveryForKubernetes', isEnabled: 'True' }
      { name: 'AgentlessVmScanning', isEnabled: 'True' }
      { name: 'ContainerSensor', isEnabled: 'True' }
    ], enableSecurityFindingsExtension ? [
      { name: 'ContainerIntegrityContribution', isEnabled: 'True' }
    ] : [])
  }
}

// ---- Defender for AI Services: model-call threat protection + evidence -----
resource ai 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'AI'
  dependsOn: [ containers ]
  properties: {
    pricingTier: 'Standard'
    extensions: [
      { name: 'AIPromptEvidence', isEnabled: 'True' }
    ]
  }
}

// ---- Defender for Storage (cheap, gives the app-data layer a control) ------
resource storage 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'StorageAccounts'
  dependsOn: [ ai ]
  properties: {
    pricingTier: 'Standard'
    subPlan: 'DefenderForStorageV2'
  }
}

output workspaceUsed string = workspaceResourceId
output note string = 'Defender CSPM, Containers, AI, Storage enabled. GATED DEPLOYMENT needs FOUR things: (1) Defender sensor + (2) Security Gating - both set per-cluster in modules/aks.bicep; (3) Registry access - enabled here; (4) SECURITY FINDINGS - NOT settable via Azure Policy and not in the documented pricings schema, so verify/toggle it: run `make verify-gating`, or portal > Environment settings > Containers > Settings > Registry access > Security findings.'
output gatedDeploymentChecklist array = [
  'Defender sensor              -> cluster securityProfile.defender.securityMonitoring (aks.bicep)'
  'Security Gating              -> cluster securityProfile.defender.securityGating (aks.bicep)'
  'Registry access              -> ContainerRegistriesVulnerabilityAssessments (this module)'
  'Security findings            -> ContainerIntegrityContribution (this module, on by default); verify with make verify-gating'
]
