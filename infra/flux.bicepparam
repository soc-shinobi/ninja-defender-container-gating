using 'modules/flux.bicep'

param aksName = readEnvironmentVariable('AKS_NAME', 'defdemo-aks')
param gitRepoUrl = readEnvironmentVariable('GIT_REPO_URL', 'https://github.com/pisinger/ninja-defender-container-gating')
param gitRepoToken = readEnvironmentVariable('FLUX_GITHUB_TOKEN', '')
param gitBranch = 'main'
param kustomizePath = './app/k8s'
param acrLoginServer = readEnvironmentVariable('ACR_LOGIN_SERVER', '')
