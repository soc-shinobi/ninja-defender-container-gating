// VNet + egress-only NSG for the Container Apps environment.
// OPT-IN: only deployed when enableAcaVnet is true in main.bicep. See ACA-readme.md for
// the cost (~$26/month for the managed load balancer and two public IPs) and the caveats.
//
// This restricts where the control panel may CALL OUT to. It does not restrict inbound:
// on an external workload-profile environment, ingress reaches the platform public IP and
// never traverses this subnet, so inbound NSG rules are not supported there.

param location string
param namePrefix string

@description('Address space for the lab VNet.')
param vnetAddressPrefix string = '10.60.0.0/16'

@description('Subnet for the Container Apps environment. /27 is the documented minimum and subnets cannot be resized later.')
param acaSubnetPrefix string = '10.60.0.0/26'

@description('Name of the environment subnet. Must match what workload.bicep computes.')
param subnetName string = 'aca-infra'

@description('AKS API server public IP. Empty falls back to the regional AzureCloud tag, which is far broader. See ACA-readme.md section 6.')
param aksApiServerIp string = ''

@description('Allow egress to Foundry / Azure AI Services. Follows deployFoundry.')
param allowFoundry bool = false

// Service tags use the region without spaces, e.g. Storage.swedencentral.
var regionTag = replace(location, ' ', '')

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-aca-nsg'
  location: location
  properties: {
    securityRules: concat([
      {
        name: 'Allow-Subnet-Internal'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: acaSubnetPrefix
          destinationPortRange: '*'
          description: 'Envoy sidecar to Envoy service, and general intra-subnet traffic.'
        }
      }
      {
        name: 'Allow-Azure-DNS'
        properties: {
          priority: 110
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '168.63.129.16'
          destinationPortRange: '53'
          description: 'Azure DNS. Never deny this: the environment stops working.'
        }
      }
      {
        name: 'Allow-Entra-ID'
        properties: {
          priority: 120
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureActiveDirectory'
          destinationPortRange: '443'
          description: 'Managed identity tokens, EasyAuth sign-in, Microsoft Graph.'
        }
      }
      {
        name: 'Allow-MCR'
        properties: {
          priority: 130
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'MicrosoftContainerRegistry'
          destinationPortRange: '443'
          description: 'Microsoft Artifact Registry, for platform system containers.'
        }
      }
      {
        name: 'Allow-Front-Door-First-Party'
        properties: {
          priority: 140
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureFrontDoor.FirstParty'
          destinationPortRange: '443'
          description: 'Documented dependency of the MicrosoftContainerRegistry tag.'
        }
      }
      {
        name: 'Allow-ACR'
        properties: {
          priority: 150
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureContainerRegistry'
          destinationPortRange: '443'
          description: 'Pull the panel image from the lab ACR.'
        }
      }
      {
        name: 'Allow-ACR-Storage'
        properties: {
          priority: 160
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'Storage.${regionTag}'
          destinationPortRange: '443'
          description: 'ACR layer data endpoints are backed by Storage.'
        }
      }
      {
        name: 'Allow-Azure-Monitor'
        properties: {
          priority: 170
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'AzureMonitor'
          destinationPortRange: '443'
          description: 'Container console and system logs to Log Analytics.'
        }
      }
      {
        name: 'Allow-AKS-API-Server'
        properties: {
          priority: 180
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          // There is NO NSG service tag for the AKS API server. AzureKubernetesService is an
          // Azure Firewall FQDN tag and is rejected here. Pin the IP via aksApiServerIp for a
          // tight rule, but re-check it after every cluster stop/start.
          destinationAddressPrefix: empty(aksApiServerIp) ? 'AzureCloud.${regionTag}' : aksApiServerIp
          destinationPortRange: '443'
          description: 'Control panel to the AKS API server: pod list, exec, jobs.'
        }
      }
    ], allowFoundry ? [
      {
        name: 'Allow-Foundry'
        properties: {
          priority: 190
          direction: 'Outbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: acaSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: 'CognitiveServicesManagement'
          destinationPortRange: '443'
          description: 'Foundry model inference from the optional chat panel.'
        }
      }
    ] : [], [
      {
        name: 'Deny-All-Outbound'
        properties: {
          priority: 4096
          direction: 'Outbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Everything not allowed above is dropped. This is the point of the exercise.'
        }
      }
    ])
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: { addressPrefixes: [ vnetAddressPrefix ] }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: acaSubnetPrefix
          networkSecurityGroup: { id: nsg.id }
          delegations: [
            {
              name: 'aca-delegation'
              properties: { serviceName: 'Microsoft.App/environments' }
            }
          ]
        }
      }
    ]
  }
}

output subnetId string = vnet.properties.subnets[0].id
output vnetName string = vnet.name
output nsgName string = nsg.name
