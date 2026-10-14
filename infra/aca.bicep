// ACA-only deployment. Used for regional capacity fallback without touching AKS or
// the rest of the core lab. All dependencies are existing resources in the RG.
targetScope = 'resourceGroup'

param location string
param namePrefix string = 'defdemo'
param environmentName string
param kubectlMode string = 'demo'
param panelEntraUser string = ''
@secure()
param panelBasicPassword string = ''
param panelBasicUser string = 'panel'
@secure()
param panelApiKey string = ''
param appImage string = ''
param foundryEndpoint string = ''
param aiModelName string = 'gpt-4o-mini'
param enableAcaVnet bool = false
param acaVnetAddressPrefix string = '10.60.0.0/16'
param acaSubnetPrefix string = '10.60.0.0/26'
param aksApiServerIp string = ''

var suffix = uniqueString(resourceGroup().id)
var acrName = toLower('${namePrefix}acr${substring(suffix, 0, 6)}')
var aksName = '${namePrefix}-aks'
var lawName = '${namePrefix}-law'
var appIdentityName = '${namePrefix}-app-id'
var appName = '${namePrefix}-app'
var acaVnetName = '${namePrefix}-vnet'
var acaSubnetName = 'aca-infra'
var acaSubnetId = resourceId('Microsoft.Network/virtualNetworks/subnets', acaVnetName, acaSubnetName)

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: lawName
}

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

resource appIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: appIdentityName
}

resource aks 'Microsoft.ContainerService/managedClusters@2025-05-02-preview' existing = {
  name: aksName
}

module acaNetwork 'modules/aca-network.bicep' = if (enableAcaVnet) {
  name: 'aca-network-${replace(location, ' ', '')}'
  params: {
    location: location
    namePrefix: namePrefix
    vnetAddressPrefix: acaVnetAddressPrefix
    acaSubnetPrefix: acaSubnetPrefix
    subnetName: acaSubnetName
    aksApiServerIp: aksApiServerIp
    allowFoundry: !empty(foundryEndpoint)
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: environmentName
  location: location
  dependsOn: enableAcaVnet ? [ acaNetwork ] : []
  properties: union({
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: law.properties.customerId
        sharedKey: law.listKeys().primarySharedKey
      }
    }
  }, enableAcaVnet ? {
    vnetConfiguration: {
      infrastructureSubnetId: acaSubnetId
      internal: false
    }
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  } : {})
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: appName
  location: location
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${appIdentity.id}': {}
    }
  }
  properties: {
    managedEnvironmentId: environment.id
    configuration: {
      secrets: union(
        empty(panelEntraUser) && !empty(panelBasicPassword) ? [
          { name: 'panel-basic-password', value: panelBasicPassword }
        ] : [],
        !empty(panelApiKey) ? [
          { name: 'panel-api-key', value: panelApiKey }
        ] : [])
      ingress: {
        external: true
        targetPort: empty(appImage) ? 80 : 8080
        transport: 'auto'
      }
      registries: [
        {
          server: acr.properties.loginServer
          identity: appIdentity.id
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'app'
          image: empty(appImage) ? 'mcr.microsoft.com/k8se/quickstart:latest' : appImage
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: union([
            { name: 'AKS_NAME', value: aksName }
            { name: 'AKS_API_FQDN', value: aks.properties.fqdn }
            { name: 'AKS_RESOURCE_ID', value: aks.id }
            { name: 'RUNNER_NAMESPACE', value: 'demo-ops' }
            { name: 'ALERT_SIM_IMAGE', value: '${acr.properties.loginServer}/mdc-alert-triage:latest' }
            { name: 'ALERT_SIM_NAMESPACE', value: 'demo-ops' }
            { name: 'KUBECTL_MODE', value: kubectlMode }
            { name: 'AZURE_CLIENT_ID', value: appIdentity.properties.clientId }
            { name: 'APP_IDENTITY_CLIENT_ID', value: appIdentity.properties.clientId }
            { name: 'FOUNDRY_ENDPOINT', value: foundryEndpoint }
            { name: 'AI_MODEL_NAME', value: aiModelName }
          ], empty(panelEntraUser) && !empty(panelBasicPassword) ? [
            { name: 'BASIC_AUTH_USER', value: panelBasicUser }
            { name: 'BASIC_AUTH_PASSWORD', secretRef: 'panel-basic-password' }
          ] : [], !empty(panelApiKey) ? [
            { name: 'PANEL_API_KEY', secretRef: 'panel-api-key' }
          ] : [])
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 1
      }
    }
  }
}

output acaAppUrl string = 'https://${app.properties.configuration.ingress.fqdn}'
output acaEnvironmentName string = environment.name
output acaLocation string = environment.location
output acaNetworkMode string = enableAcaVnet ? 'vnet-integrated' : 'platform-managed'
