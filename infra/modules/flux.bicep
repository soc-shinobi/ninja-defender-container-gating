// =============================================================================
// GitOps with Flux on AKS - Microsoft's first-party GitOps path, as pure Bicep.
//
// Two ARM resources, no scripts. Public repos work without a token; private repos
// use the optional PAT through ARM protected settings, never a plain template parameter:
//   1. Microsoft.KubernetesConfiguration/extensions  (type microsoft.flux)
//   2. Microsoft.KubernetesConfiguration/fluxConfigurations
//
// Demo beat (Act 4): Flux reconciles separate blocked and allowed Kustomizations.
// The blocked path reaches the Defender admission webhook and reports NotReady;
// the allowed path reports readiness independently.
//
// THE TRAP THIS CONFIG AVOIDS: the gate is an admission webhook on POD creation.
// A Deployment and its ReplicaSet are perfectly legal objects, so Flux applies them
// happily and reports Ready=True while no pod ever starts - the denial text lands in
// ReplicaSet events, which nobody watches. `wait: true` makes Flux health-check what
// it applied, so the Kustomization actually goes Ready=False and the ARM compliance
// state turns Non-compliant. Without it, GitOps reports green over a blocked rollout.
//
// The ACR login server is injected via Flux postBuild substitution in each path.
//
// Ref (verified 2026-09-18):
//   https://learn.microsoft.com/azure/azure-arc/kubernetes/conceptual-gitops-flux2
//   https://learn.microsoft.com/azure/azure-arc/kubernetes/tutorial-use-gitops-flux2
// =============================================================================

@description('AKS cluster name (in this resource group).')
param aksName string

@description('HTTPS URL of this repo, e.g. https://github.com/<you>/ninja-session-demo-defender')
param gitRepoUrl string

@description('Optional GitHub PAT used as the HTTPS password when the repository is private.')
@secure()
param gitRepoToken string = ''

@description('Branch to sync.')
param gitBranch string = 'main'

@description('Root path in the repo containing separate base, x-mdc-blocked, and x-mdc-allowed Kustomizations.')
param kustomizePath string = './app/k8s'

@description('ACR login server. Flux postBuild substitutes it into the manifests as the ACR_LOGIN_SERVER variable.')
param acrLoginServer string

@description('Health-check what Flux applies (Kustomization wait). Leave true: without it an admission denial on pods leaves the Kustomization green while nothing runs. See the note at the top of this file.')
param waitForHealth bool = true

@description('How long Flux waits for the applied workloads to become healthy before reporting failure. Must exceed a realistic pod start time, or a slow pull looks like a denial.')
param healthTimeoutInSeconds int = 600

@description('Turn on the Flux notification-controller so Provider/Alert objects can push failures to GitHub commit status and a chat webhook. See app/k8s/40-flux-notifications.yaml.')
param enableNotificationController bool = true

resource aks 'Microsoft.ContainerService/managedClusters@2025-05-02-preview' existing = {
  name: aksName
}

// 1. Flux cluster extension. source + kustomize always; notification-controller
//    when enabled, because a denial nobody is told about is a denial that gets
//    worked around. Helm and the image controllers stay off to keep the node light.
resource flux 'Microsoft.KubernetesConfiguration/extensions@2023-05-01' = {
  name: 'flux'
  scope: aks
  properties: {
    extensionType: 'microsoft.flux'
    autoUpgradeMinorVersion: true
    releaseTrain: 'Stable'
    scope: {
      cluster: {
        releaseNamespace: 'flux-system'
      }
    }
    configurationSettings: {
      'source-controller.enabled': 'true'
      'kustomize-controller.enabled': 'true'
      'helm-controller.enabled': 'false'
      'notification-controller.enabled': enableNotificationController ? 'true' : 'false'
      'image-automation-controller.enabled': 'false'
      'image-reflector-controller.enabled': 'false'
    }
  }
}

// 2. Flux configuration: reconcile shared resources and both workload scenarios separately.
resource demoApps 'Microsoft.KubernetesConfiguration/fluxConfigurations@2023-05-01' = {
  name: 'demo-apps'
  scope: aks
  dependsOn: [ flux ]
  properties: {
    scope: 'cluster'
    namespace: 'flux-system'
    sourceKind: 'GitRepository'
    suspend: false
    gitRepository: {
      url: gitRepoUrl
      httpsUser: empty(gitRepoToken) ? '' : 'x-access-token'
      repositoryRef: {
        branch: gitBranch
      }
      syncIntervalInSeconds: 60
      timeoutInSeconds: 120
    }
    configurationProtectedSettings: empty(gitRepoToken) ? {} : {
      httpsKey: base64(gitRepoToken)
    }
    kustomizations: {
      base: {
        path: '${kustomizePath}/base'
        prune: true
        force: false
        wait: true
        syncIntervalInSeconds: 60
        retryIntervalInSeconds: 300
        timeoutInSeconds: healthTimeoutInSeconds
      }
      blocked: {
        path: '${kustomizePath}/x-mdc-blocked'
        dependsOn: [ 'base' ]
        prune: true
        force: false
        wait: waitForHealth
        syncIntervalInSeconds: 60
        retryIntervalInSeconds: 300
        timeoutInSeconds: healthTimeoutInSeconds
        postBuild: {
          substitute: {
            ACR_LOGIN_SERVER: acrLoginServer
          }
        }
      }
      allowed: {
        path: '${kustomizePath}/x-mdc-allowed'
        dependsOn: [ 'base' ]
        prune: true
        force: false
        wait: waitForHealth
        syncIntervalInSeconds: 60
        retryIntervalInSeconds: 300
        timeoutInSeconds: healthTimeoutInSeconds
        postBuild: {
          substitute: {
            ACR_LOGIN_SERVER: acrLoginServer
          }
        }
      }
    }
  }
}

output fluxConfigurationName string = demoApps.name
output note string = 'Check state: az k8s-configuration flux show -g <rg> -c ${aksName} -n demo-apps -t managedClusters   (or: make flux-status)'
