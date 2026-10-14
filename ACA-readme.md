# Locking down Container Apps egress with a network security group

Putting the AKS control panel into a virtual network and restricting its outbound traffic.

**This is implemented and off by default.** The lab deploys the Container Apps environment on
the Microsoft-managed network unless you opt in:

```bash
ENABLE_ACA_VNET=true make deploy                            # egress NSG, ~$26/month
ENABLE_ACA_VNET=true AKS_API_SERVER_IP=<ip> make deploy     # and pin the API server rule
```

The implementation lives in `infra/modules/aca-network.bicep`, switched by `enableAcaVnet` in
`infra/main.bicepparam`. With the flag off, no network resources are created at all and there
is no extra cost. The deployment prints which mode it used, and `main.bicep` outputs it as
`acaNetworkMode`.

Everything here was checked against Microsoft Learn and the Azure retail price API on
2026-09-19. The Bicep compiles with zero errors and zero warnings.

---

## 1. Why this is a switch and not just a rule

A network security group attaches to a **subnet**. With `enableAcaVnet` off, the Container Apps
environment has no `vnetConfiguration`, runs on Microsoft's own network, and there is no subnet
in the subscription to attach anything to. There is no "just add an NSG" option. Restricting
egress means the environment must be *created* inside a virtual network, which is why this is a
deploy-time flag rather than something you can toggle later.

## 2. What it costs

Virtual networks and network security groups are free. The cost comes from the managed
resource group that Azure creates in **your** subscription when an environment joins your
network. For an internet-facing workload-profile environment you are billed for one standard
load balancer plus two standard static public IPs, one for ingress and one for egress.

| Item | Rate | Per month at 730h |
| --- | --- | --- |
| Standard load balancer, fewer than 6 rules | $0.025/h | $18.25 |
| Standard static public IP, ingress | $0.005/h | $3.65 |
| Standard static public IP, egress | $0.005/h | $3.65 |
| **Total** | **$0.035/h** | **$25.55** |

Data processed adds $0.005/GB, which is pennies here. Load balancer meters are billed globally;
the IP rate is the Sweden Central one.

**Nightly parking does not reduce this.** `scripts/lab-park.sh` scales the app to zero replicas,
but the load balancer and both IPs belong to the *environment*, not the app. They bill around
the clock for as long as the environment exists. The only way to stop the meter is deleting the
environment, which changes the panel hostname every morning and breaks the Entra redirect URI.
Treat it as a flat charge.

**What does not cost extra:** the Dedicated plan management fee applies only if you add a
Dedicated workload profile. Staying on the Consumption profile means compute billing, the
monthly free grants and scale-to-zero all behave exactly as they do now.

## 3. Pick the workload-profile environment, not consumption-only

This choice decides how tight the rule set can be, so it matters more than it looks.

| | Workload profiles (v2) | Consumption-only (v1, legacy) |
| --- | --- | --- |
| Minimum subnet | `/27` | `/23` |
| Subnet delegation | required, `Microsoft.App/environments` | must NOT be delegated |
| Egress rules needed | the tight list in section 5 | that list **plus** all outbound on 443 to `AzureCloud`, plus AKS ports 1194 and 9000, plus Event Hubs 5671/5672, plus NTP 123 |
| User-defined routes, NAT gateway | supported | not supported |

Consumption-only requires allowing all outbound on 443 to the entire Azure cloud, which throws
away most of the benefit. Use workload profiles.

## 4. Subnet rules worth knowing before you commit

- Minimum `/27`. The platform reserves 12 addresses, and single-revision deployments briefly
  double the requirement.
- **A subnet cannot be resized once an environment uses it.** Address space is free, so take a
  `/26` and stop worrying.
- Delegate to `Microsoft.App/environments`.
- The range must not overlap `169.254.0.0/16`, `172.30.0.0/16`, `172.31.0.0/16`, `192.0.2.0/24`,
  and for workload profiles also `100.100.0.0/17`, `100.100.128.0/19`, `100.100.160.0/19` and
  `100.100.192.0/19`.
- The subnet is exclusive to the environment. Nothing else may live in it.

## 5. The egress rule set

Platform requirements come from the Container Apps firewall-integration doc. The rest are what
this particular panel needs: an Entra token, the AKS API server, its own image, and logs.

| Pri | Name | Proto | Destination | Port | Why |
| --- | --- | --- | --- | --- | --- |
| 100 | Allow-Subnet-Internal | Any | the subnet itself | any | Envoy sidecar to Envoy service |
| 110 | Allow-Azure-DNS | Any | `168.63.129.16` | 53 | name resolution |
| 120 | Allow-Entra-ID | TCP | `AzureActiveDirectory` | 443 | managed identity tokens, EasyAuth sign-in, Graph |
| 130 | Allow-MCR | TCP | `MicrosoftContainerRegistry` | 443 | platform system containers |
| 140 | Allow-Front-Door-First-Party | TCP | `AzureFrontDoor.FirstParty` | 443 | documented dependency of the tag above |
| 150 | Allow-ACR | TCP | `AzureContainerRegistry` | 443 | pull the panel image |
| 160 | Allow-ACR-Storage | TCP | `Storage.<region>` | 443 | ACR layer data endpoints |
| 170 | Allow-Azure-Monitor | TCP | `AzureMonitor` | 443 | console and system logs |
| 180 | Allow-AKS-API-Server | TCP | see section 6 | 443 | pod list, exec, jobs |
| 190 | Allow-Foundry | TCP | `CognitiveServicesManagement` | 443 | only if the chat panel is deployed |
| 4096 | Deny-All-Outbound | Any | any | any | the actual control |

Two traps:

- **Never deny `168.63.129.16`.** Microsoft calls this out explicitly. The environment stops
  working, and the failure does not look like a DNS problem.
- `CognitiveServicesManagement` is the tag that covers Foundry traffic. Leave it out unless the
  optional chat panel is deployed.

## 6. The AKS API server is the awkward one

The panel's whole job is reaching the AKS API server, and **there is no network security group
service tag for it**. `AzureKubernetesService` exists, but it is an Azure **Firewall FQDN tag**,
not an NSG service tag, because it resolves fully-qualified domain names and a network security
group filters on addresses only. It will be rejected.

Two workable options:

1. **`AzureCloud.<region>` on 443.** Always works, survives the API server IP changing, and is
   honestly quite broad: it permits every regional Azure endpoint on 443, which makes several of
   the narrower rules above redundant. Fine for a lab, weak as a claim on a slide.
2. **Pin the API server's public IP.** Genuinely tight. The catch is that the address is only
   known after the cluster exists and **can change across a stop/start cycle**, which this lab
   does every night. If you pin it, have `scripts/lab-start.sh` re-resolve and update the rule
   on each start, or some mornings the panel will simply stop working with no obvious cause.

```bash
# resolve the current API server IP
AKS_FQDN=$(az aks show -g "$RG" -n "$AKS" --query fqdn -o tsv)
AKS_IP=$(dig +short "$AKS_FQDN" | tail -1)

# repoint the rule at it
az network nsg rule update -g "$RG" --nsg-name "${PREFIX}-aca-nsg" \
  -n Allow-AKS-API-Server --destination-address-prefixes "$AKS_IP"
```

The honest framing for a talk: option 1 is what most people ship, and it is worth saying out
loud that a regional cloud tag on 443 is a long way from a tight rule.

## 7. Limits to be clear about

- **Inbound cannot be controlled this way.** On an internet-facing workload-profile environment,
  inbound traffic reaches the platform public IP in the managed resource group and never
  traverses your subnet. Microsoft states that locking inbound down via a network security group
  is not supported there. This design controls **egress only**. Authentication remains the
  access control for the panel.
- **The network type is immutable.** An existing environment cannot be moved into a virtual
  network. This is a delete and recreate, which produces a new hostname, so the Entra app's
  redirect URI must be updated and `make auth` re-run.
- **This constrains the platform, not the cluster.** Someone who reaches the panel still has its
  managed identity and its Kubernetes permissions. Egress rules limit where a compromised
  container can *call out* to. They do not narrow what the panel is allowed to do to AKS.
- Network security group flow logs are extra cost and are not included here.

## 8. The implementation

This ships as `infra/modules/aca-network.bicep`, deployed conditionally from `workload.bicep`.
Reproduced here so the note stands alone. Two details worth copying if you rebuild this
elsewhere: the subnet ID is computed with `resourceId()` rather than read from the conditional
module's output, so nothing dereferences a module that was not deployed; and the `dependsOn` is
harmless when the flag is off, because Azure Resource Manager skips dependencies on resources
whose condition is false.

```bicep
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
```

And the wiring in `workload.bicep`:

```bicep
var acaVnetName = '${namePrefix}-vnet'
var acaSubnetName = 'aca-infra'
var acaSubnetId = resourceId('Microsoft.Network/virtualNetworks/subnets', acaVnetName, acaSubnetName)

module acaNetwork 'aca-network.bicep' = if (enableAcaVnet) {
  name: 'aca-network'
  params: {
    location: location
    namePrefix: namePrefix
    vnetAddressPrefix: acaVnetAddressPrefix
    acaSubnetPrefix: acaSubnetPrefix
    subnetName: acaSubnetName
    aksApiServerIp: aksApiServerIp
    allowFoundry: deployFoundry
  }
}

resource acaEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: acaEnvName
  location: location
  dependsOn: enableAcaVnet ? [ acaNetwork ] : []
  properties: union({
    appLogsConfiguration: { /* unchanged */ }
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
```

The `workloadProfiles` array is what makes this a v2 environment. Leave it out and you get the
legacy consumption-only type with the much weaker rule set from section 3.

## 9. Verifying it after deployment

```bash
# effective rules actually applied to the subnet
az network nsg rule list -g "$RG" --nsg-name "${PREFIX}-aca-nsg" \
  -o table --query "sort_by([?direction=='Outbound'], &priority)[].{p:priority,n:name,a:access,dst:destinationAddressPrefix,port:destinationPortRange}"

# confirm the environment really is in your subnet and is workload-profile type
az containerapp env show -g "$RG" -n "$ACA_ENV" \
  --query "{subnet:properties.vnetConfiguration.infrastructureSubnetId, profiles:properties.workloadProfiles[].name}"
```

Then exercise the panel itself, because a rule set that looks right and a panel that works are
different claims: list pods, open a kubectl session, run the alert simulation, and sign out and
back in to prove the Entra path still resolves.

The useful negative test for a talk: temporarily add a deny rule above priority 180 and show the
panel losing the cluster while its health probe stays green. That demonstrates egress control
doing something, which a table of allow rules never does.

## 10. Sources

- Network security groups in Container Apps: <https://learn.microsoft.com/azure/container-apps/firewall-integration>
- Virtual network configuration, subnets and managed resources: <https://learn.microsoft.com/azure/container-apps/custom-virtual-networks>
- Container Apps billing: <https://learn.microsoft.com/azure/container-apps/billing>
- Service tags, including the note that `AzureKubernetesService` is a firewall FQDN tag: <https://learn.microsoft.com/azure/virtual-network/service-tags-overview>
- AKS outbound rules: <https://learn.microsoft.com/azure/aks/outbound-rules-control-egress>
- Prices from the Azure retail price API, `https://prices.azure.com/api/retail/prices`, 2026-09-19
