// AcrPull for a principal whose object ID is only known once another resource exists.
// A role assignment's NAME must be computable at the start of the deployment, so a guid()
// over a module output is rejected (BCP120). Passing the ID into a module makes it a
// parameter, which is available when this nested deployment starts.
@description('Registry that the principal may pull from.')
param acrName string

@description('Object (principal) ID to grant AcrPull to.')
param principalId string

var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acr 'Microsoft.ContainerRegistry/registries@2023-11-01-preview' existing = {
  name: acrName
}

resource pull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, principalId, acrPullRoleId)
  scope: acr
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
    principalType: 'ServicePrincipal'
  }
}
