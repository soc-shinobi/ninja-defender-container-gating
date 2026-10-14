// =============================================================================
// AKS for the demo lab: smallest practical node, ephemeral (non-persistent)
// OS disk, Cilium network policy (needed for XDR isolate-pod), OIDC issuer +
// workload identity (needed for gated deployment), and the Defender
// securityProfile with security gating enabled.
//
// Schema verified from Microsoft.ContainerService/managedClusters
// 2025-05-02-preview on 2026-09-18.
// =============================================================================

@description('Location.')
param location string

@description('AKS cluster name.')
param aksName string

@description('Node VM size. Must support an ephemeral OS disk (temp disk >= 30 GiB).')
param nodeVmSize string = 'Standard_D2ds_v5'

@description('System node count. TWO by default, and that is not padding: the Defender security-gating admission controller alone requests 600m CPU and the sensor DaemonSet another 80m per node. A single Standard_D2ds_v5 offers 1900m allocatable, of which the AKS system pods (CoreDNS, metrics-server, Cilium, workload-identity webhook), Container Insights and the Azure Policy gatekeeper already request ~1830m - so both Defender pods sit Pending forever on one node, and gating silently never enforces.')
@minValue(1)
param nodeCount int = 2

@description('Log Analytics workspace resource ID for Defender + Container Insights.')
param logAnalyticsId string

@description('Resource ID of the user-assigned identity the gating admission controller uses to pull findings artifacts from ACR.')
param gatingIdentityResourceId string

@description('Client ID of the gating identity. Sent with resourceId and objectId: the identity schema takes all three, and Microsoft\'s guide names the objectId explicitly.')
param gatingIdentityClientId string = ''

@description('Object (principal) ID of the gating identity.')
param gatingIdentityObjectId string = ''

@description('ACR login server the gating identity is scoped to (e.g. myacr.azurecr.io).')
param acrLoginServer string

@description('Send securityGating.identities inside the cluster body. The field is documented from api-version 2025-05-02-preview onwards, but the ContainerService resource provider rejected it in swedencentral on 2026-09-19 (UnmarshalError: unknown field "identities") on both 2025-05-02-preview and 2026-02-02-preview. Leave false to create the cluster, then attach the identity afterwards with infra/postdeploy/attach-gating-identity.sh (scripts/deploy.sh runs it; make gating-identity on its own). The gating identity, its AcrPull role and its federated credential are created either way.')
param attachGatingIdentities bool = false

@description('Azure Policy for Kubernetes (the gatekeeper add-on). OFF by default: it costs three gatekeeper pods plus two azure-policy pods (~300m CPU of requests) and this lab does not need it - Defender enforces its misconfiguration rules as ValidatingAdmissionPolicies from the Helm sensor, not through gatekeeper constraints. Note that enabling the Defender for Containers plan can switch this add-on back on by itself.')
param deployAzurePolicy bool = false

@description('Azure Disk/File CSI drivers and the snapshot controller. OFF by default: this lab stores nothing persistently - no PersistentVolumeClaim exists and every pod volume is hostPath, projected, configMap, secret or emptyDir - so the drivers only add two DaemonSets (four pods on a two-node cluster) to every `kubectl get pods -A` during a talk. Turn it on before adding any workload that needs a PVC.')
param deployCsiDrivers bool = false

@description('Container Insights (the omsagent / ama-logs add-on). OFF by default: it adds an ama-logs DaemonSet pod per node plus a replicaset pod, ~300m CPU of requests in total, which on a small lab node competes with the Defender sensor and the gating admission controller. Defender does not need it - its telemetry goes to Defender for Cloud, not to the workspace.')
param deployContainerInsights bool = false

@description('Provision the Defender sensor via Helm instead of the AKS add-on. Needed for binary drift BLOCKING and antimalware. Sets the auto-provisioning exclusion tag and disables the add-on sensor + gating (the Helm chart ships its own admission controller). Then run infra/postdeploy/install-defender-helm.sh.')
param defenderSensorViaHelm bool = false

resource aks 'Microsoft.ContainerService/managedClusters@2026-02-02-preview' = {
  name: aksName
  location: location
  // Must be present BEFORE Defender auto-provisions the sensor, or you get two sensors.
  // NOT ms_defender_e2e_discovery_exclude: Microsoft documents that one for Arc clusters in
  // AWS/GCP. On AKS it keeps Defender's discovery away, and discovery is what creates the
  // Trusted Access bindings that push gating and misconfiguration rules into the cluster.
  tags: defenderSensorViaHelm ? { ms_defender_container_exclude_sensors: 'true' } : {}
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: aksName
    // OIDC issuer + workload identity: required by gated deployment.
    oidcIssuerProfile: {
      enabled: true
    }
    // Entra-integrated auth with Azure RBAC for Kubernetes authorization. This is what lets
    // the Container App control panel reach the API server with its managed identity, with
    // permissions granted as Azure role assignments (namespace-scoped) instead of a kubeconfig.
    aadProfile: {
      managed: true
      enableAzureRBAC: true
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
      // Defender sensor (threat detection) + security gating (admission).
      // HELM PATH: the whole add-on is switched off and the workspace ID must go with it -
      // sending one while the profile is disabled fails preflight with
      // "AzureDefender is disabled but Log Analytics workspace resource ID is not empty".
      // The chart then installs the sensor into the mdc namespace (see
      // infra/postdeploy/install-defender-helm.sh); kube-system is the add-on's namespace,
      // and on AKS Automatic the Helm sensor goes to kube-system instead.
      defender: defenderSensorViaHelm ? {
        securityMonitoring: {
          enabled: false
        }
      } : {
        logAnalyticsWorkspaceResourceId: logAnalyticsId
        securityMonitoring: {
          enabled: true
        }
        securityGating: attachGatingIdentities ? {
          enabled: true
          identities: [
            {
              azureContainerRegistry: acrLoginServer
              identity: {
                resourceId: gatingIdentityResourceId
                clientId: gatingIdentityClientId
                objectId: gatingIdentityObjectId
              }
            }
          ]
        } : {
          enabled: true
        }
      }
    }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: nodeCount
        vmSize: nodeVmSize
        // Non-persistent OS disk: wiped on reimage. The whole point of "ephemeral".
        osDiskType: 'Ephemeral'
        osDiskSizeGB: 30
        osType: 'Linux'
        osSKU: 'AzureLinux'
        type: 'VirtualMachineScaleSets'
        enableAutoScaling: false
        maxPods: 50
      }
    ]
    // The snapshot controller cannot outlive the disk driver, so all three move together.
    storageProfile: {
      diskCSIDriver: {
        enabled: deployCsiDrivers
      }
      fileCSIDriver: {
        enabled: deployCsiDrivers
      }
      snapshotController: {
        enabled: deployCsiDrivers
      }
    }
    // Azure CNI Overlay + Cilium data plane + Cilium network policy.
    // The network policy engine is what makes the XDR "isolate pod" action work.
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
    }
    addonProfiles: {
      azurePolicy: {
        enabled: deployAzurePolicy
      }
      // Same rule as the Defender profile: a disabled add-on must not carry a workspace ID.
      omsagent: deployContainerInsights ? {
        enabled: true
        config: {
          logAnalyticsWorkspaceResourceID: logAnalyticsId
        }
      } : {
        enabled: false
      }
    }
    disableLocalAccounts: false
  }
}

output aksName string = aks.name
output aksId string = aks.id
output oidcIssuerUrl string = aks.properties.oidcIssuerProfile.issuerURL
output aksFqdn string = aks.properties.fqdn
output kubeletIdentityObjectId string = aks.properties.identityProfile.kubeletidentity.objectId
