using 'modules/flux.bicep'

param aksName = readEnvironmentVariable('AKS_NAME', 'defdemo-aks')
// No fallback: scripts/update-flux-auth.sh derives it from the repo the workflow runs in.
param gitRepoUrl = readEnvironmentVariable('GIT_REPO_URL')
param gitRepoToken = readEnvironmentVariable('FLUX_GITHUB_TOKEN', '')
param gitBranch = 'main'
param kustomizePath = './app/k8s'
param acrLoginServer = readEnvironmentVariable('ACR_LOGIN_SERVER', '')
param heartbeatUrl = readEnvironmentVariable('HEARTBEAT_URL', '')
