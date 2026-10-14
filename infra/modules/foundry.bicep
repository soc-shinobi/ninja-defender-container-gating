// =============================================================================
// Azure AI Foundry: AI Services account + project + one model deployment.
// The model deployment is what Defender for AI Services protects (mode A:
// direct model inference). Mode B (chat with a published agent) needs a
// Microsoft Agent 365 license and is created as a post-deploy step, not here.
//
// Verified against Microsoft.CognitiveServices/accounts schema 2026-09-18.
// =============================================================================

param location string
param foundryName string
param modelName string
param modelVersion string
param appIdentityPrincipalId string
param adminPrincipalId string
param openAiUserRoleId string

// AI Services account with project management enabled (Foundry).
resource account 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: foundryName
  location: location
  sku: { name: 'S0' }
  kind: 'AIServices'
  identity: { type: 'SystemAssigned' }
  properties: {
    customSubDomainName: foundryName
    allowProjectManagement: true
    publicNetworkAccess: 'Enabled'
    // enableDefenderForAI mirrors the subscription AI plan at resource level.
    // Defender for AI Services threat protection covers this endpoint.
  }
}

resource project 'Microsoft.CognitiveServices/accounts/projects@2025-06-01' = {
  parent: account
  name: '${foundryName}-proj'
  location: location
  identity: { type: 'SystemAssigned' }
  properties: {
    displayName: 'Defender demo project'
    description: 'Model inference (Defender for AI) + agent host (Agent 365) for the code-to-runtime demo.'
  }
}

resource deployment 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = {
  parent: account
  name: modelName
  sku: {
    name: 'GlobalStandard'
    capacity: 20
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: modelName
      version: modelVersion
    }
  }
}

// The Container App's identity can call the model (mode A).
resource appModelUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(account.id, appIdentityPrincipalId, openAiUserRoleId)
  scope: account
  properties: {
    principalId: appIdentityPrincipalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', openAiUserRoleId)
    principalType: 'ServicePrincipal'
  }
}

// You (admin) can use the playground.
resource adminModelUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(adminPrincipalId)) {
  name: guid(account.id, adminPrincipalId, openAiUserRoleId)
  scope: account
  properties: {
    principalId: adminPrincipalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', openAiUserRoleId)
  }
}

output endpoint string = account.properties.endpoint
output accountName string = account.name
output projectName string = project.name
