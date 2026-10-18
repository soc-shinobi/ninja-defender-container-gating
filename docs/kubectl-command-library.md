# kubectl command library

Every kubectl command the control panel (`app/webapp`, the ACA web app) runs, with a short
explanation. All of them run in the in-cluster `kubectl-runner` pod (`demo-ops`), through the
AKS API server, so they are authenticated, authorized and audited. There is no shell: a `|`
after the command runs in the panel (grep, head, tail, wc, sort, uniq, column), not in the pod.

`<acr>` is your registry (`ACR_LOGIN_SERVER`). Commands that create or delete need
`KUBECTL_MODE=demo`; `readonly` allows only get, describe, logs, top and similar.

Taken from `app/webapp/app.py`. Three long commands are shown in short form (`<...>`
placeholders): the panel's command library has the full text.

## Cluster

| Command | What it does |
|---|---|
| `kubectl get nodes -o wide` | Every node with status, version, internal IP, OS image and container runtime. |
| `kubectl get namespaces` | All namespaces and their age. |
| `kubectl get pods -A -o wide` | Every pod in every namespace with node and pod IP. |
| `kubectl get pods -A --field-selector=status.phase!=Running` | Pods that are Pending, Failed or Succeeded - the quick way to spot trouble. |
| `kubectl top nodes` | Current CPU and memory per node (metrics-server). |
| `kubectl top pods -A` | Current CPU and memory per pod, all namespaces. |
| `kubectl get events -A --sort-by=.lastTimestamp` | Cluster events, newest last: scheduling, image pulls, admission denials, restarts. |
| `kubectl api-resources --verbs=list -o name` | Every listable resource type, including the Defender and Flux CRDs. |

## Defender sensor

| Command | What it does |
|---|---|
| `kubectl get pods -n mdc -o wide` | The Defender sensor pods in the `mdc` namespace. |
| `kubectl get daemonset,deployment -n mdc` | The sensor's DaemonSets (per-node collectors) and Deployments (admission controller). |
| `kubectl logs -n mdc deploy/defender-admission-controller --tail=100` | Recent decisions and errors of the Defender admission controller (image gate). |
| `kubectl logs -n mdc ds/microsoft-defender-collector-ds --tail=100 --all-containers` | Runtime collector logs from every container of the collector DaemonSet. |
| `kubectl logs -n mdc ds/microsoft-defender-publisher-ds --tail=100` | Logs of the component that ships sensor data to Defender for Cloud. |
| `kubectl get pods -n mdc -o wide --sort-by=.status.containerStatuses[0].restartCount` | Sensor pods sorted by restart count - crash loops float to the bottom. |
| `kubectl get events -n mdc --sort-by=.lastTimestamp` | Events in the `mdc` namespace, newest last. |

## Misconfiguration policies (VAP)

| Command | What it does |
|---|---|
| `kubectl get validatingadmissionpolicies` | The ValidatingAdmissionPolicies Defender pushes for misconfiguration rules. |
| `kubectl get validatingadmissionpolicybindings` | Their bindings - the binding decides whether a rule audits or denies. |
| `kubectl get validatingadmissionpolicybindings -o custom-columns=NAME:.metadata.name,POLICY:.spec.policyName,ACTIONS:.spec.validationActions` | Each binding with its policy and action (`Deny`, `Audit`, `Warn`). |
| `kubectl get validatingadmissionpolicies -o yaml` | The policies as YAML, including the CEL expressions they evaluate. |
| `kubectl get policytemplates.defender.microsoft.com` | Defender's policy templates (the source of the generated admission policies). |
| `kubectl get policies.defender.microsoft.com -A` | Defender policy objects in all namespaces. |
| `kubectl get runtimepolicies.defender.microsoft.com -A` | Runtime policies (drift and similar) synced to the cluster. |
| `kubectl get crd -o name` | Every CustomResourceDefinition, to see which Defender types exist. |

## Azure Policy add-on (Gatekeeper)

Health, policy sync and what it enforces. Gatekeeper logs a violation as `denied admission` even in `dryrun`: the action column decides whether anything is blocked (`dryrun` = audit only, `deny` = blocked).

| Command | What it does |
|---|---|
| `kubectl get pods -n gatekeeper-system -o wide` | gatekeeper-audit and the two gatekeeper-controller pods: all `1/1 Running`. |
| `kubectl get pods -n kube-system -o wide -l 'app in (azure-policy,azure-policy-webhook)'` | The azure-policy pod (syncs assignments from Azure) and its webhook. |
| `kubectl get deploy -n gatekeeper-system` | Gatekeeper deployments, ready vs desired. |
| `kubectl get deploy -n kube-system azure-policy azure-policy-webhook` | Azure Policy deployments, ready vs desired. |
| `kubectl get validatingwebhookconfigurations` | Both Gatekeeper webhooks registered, next to Defender's. |
| `kubectl get constrainttemplates` | Policy definitions synced from Azure. Templates without constraints = sync not working. |
| `kubectl get constraints` | The assignments that reached the cluster. |
| `kubectl get constraints -o custom-columns=KIND:.kind,NAME:.metadata.name,ACTION:.spec.enforcementAction,VIOLATIONS:.status.totalViolations` | Each constraint with its action and violation count. |
| `kubectl get constraints -o yaml` | Full detail, including `status.violations`. |
| `kubectl logs -n kube-system deploy/azure-policy --tail=50` | Policy sync from Azure (managed identity, network). |
| `kubectl logs -n gatekeeper-system deploy/gatekeeper-audit --tail=50` | The audit that feeds Azure Policy compliance. |
| `kubectl logs -n gatekeeper-system deploy/gatekeeper-controller --tail=50` | Admission decisions, including dryrun violations. |

## Gated deployment (image gate)

| Command | What it does |
|---|---|
| `kubectl get validatingwebhookconfigurations` | All validating webhooks; the Defender image gate is one of them. |
| `kubectl describe validatingwebhookconfiguration defender-admission-controller.mdc.svc` | The gate webhook in detail: rules, namespace selector, failure policy. |
| `kubectl get securityartifactpolicies.defender.microsoft.com -A` | The gated-deployment rules Defender synced (which namespaces, which severity). |
| `kubectl get clusterrole defender-admission-controller-cluster-role -o yaml` | What the admission controller may read cluster-wide. |
| `kubectl get clusterrolebinding defender-admission-controller-cluster-role-binding -o yaml` | Who holds that role. |
| `kubectl get clusterrole defender-admission-controller-resource-cluster-role -o yaml` | Extra permissions the gate needs on Defender resources. |
| `kubectl get clusterrolebinding defender-admission-controller-cluster-resource-role-binding -o yaml` | Who holds the gating resource role. |
| `kubectl get securityartifactpolicies.defender.microsoft.com -A -o json` | The gated-deployment rules in full, as JSON. |
| `kubectl get validatingwebhookconfigurations -o custom-columns=NAME:.metadata.name,SERVICE:.webhooks[*].clientConfig.service.name,NS:.webhooks[*].clientConfig.service.namespace,PATH:.webhooks[*].clientConfig.service.path` | Each webhook with the service and namespace it calls. |
| `kubectl run gate-test --image=<acr>/aca-webapp:latest -n x-mdc-blocked --restart=Never` | Real pod with a vulnerable image in the gated namespace - the gate should deny it. |
| `kubectl run gate-test --image=<acr>/aca-webapp:latest -n x-mdc-allowed --restart=Never` | The same image outside the gate scope - it should be admitted. |
| `kubectl delete pod gate-test -n x-mdc-allowed --ignore-not-found` | Remove the admitted test pod again. |

## Flux gitops

| Command | What it does |
|---|---|
| `kubectl get kustomizations.kustomize.toolkit.fluxcd.io -A` | Flux Kustomizations and whether each is Ready. |
| `kubectl get gitrepositories.source.toolkit.fluxcd.io -A` | The Git repositories Flux pulls and the revision it has. |
| `kubectl describe kustomizations.kustomize.toolkit.fluxcd.io -n flux-system demo-apps-blocked` | Full status of the blocked Kustomization - the admission denial is in its message. |
| `kubectl get events -A --field-selector reason=FailedCreate --sort-by=.lastTimestamp` | Every pod creation the admission webhooks refused, newest last. |
| `kubectl describe rs -n x-mdc-blocked` | ReplicaSets in the gated namespace with their failed-create events. |
| `kubectl get events -n flux-system --sort-by=.lastTimestamp` | Events of the Flux controllers, newest last. |
| `kubectl logs -n flux-system deploy/kustomize-controller --tail=100` | Logs of the controller that applies the manifests. |
| `kubectl logs -n flux-system deploy/source-controller --tail=100` | Logs of the controller that fetches the Git repository. |
| `kubectl get alerts.notification.toolkit.fluxcd.io,providers.notification.toolkit.fluxcd.io -n flux-system` | Flux notification setup (the GitHub commit status). |

## Binary drift + isolation (x-mdc-allowed)

| Command | What it does |
|---|---|
| `kubectl logs -n x-mdc-allowed deploy/webapp --since=2m` | The webapp's heartbeat to the panel - `OK` lines while it has network. |
| `kubectl exec -n x-mdc-allowed deploy/webapp -- python3 -c '<netstat-style one-liner>'` | Every TCP socket of the webapp with state and process. The image has no netstat, so python3 reads `/proc/net/tcp*` (full one-liner in the panel). |
| `kubectl exec -n x-mdc-allowed deploy/webapp -- sh -c "mkdir -p /opt/mdc-drift && cp /bin/ls /opt/mdc-drift/drift-ls && /opt/mdc-drift/drift-ls -la /opt/mdc-drift"` | Runs a binary that was not in the image - triggers a Defender binary-drift alert. |
| `kubectl exec -n x-mdc-allowed deploy/webapp -- sh -c 'getent hosts poolmining.org; curl -s -m 5 -o /dev/null -w %{http_code} http://poolmining.org'` | Resolves and requests a known mining pool from the pod (curl, else python3) - triggers a crypto-mining alert. Any HTTP answer, even 403, counts. |
| `kubectl get networkpolicies -n x-mdc-allowed -o wide` | After "isolate pod" in Defender XDR, the deny-all network policy shows up here. |
| `kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,POD:.metadata.name,STATUS:.status.phase,ISOLATED:.metadata.labels.mdc-deny-all-network,RESTRICTED:.metadata.labels.mdc-block-sensitive-interfaces \| grep -wE "NAMESPACE\|true" \| column -t` | Every pod a Defender response touched, any namespace: ISOLATED = label `mdc-deny-all-network`, RESTRICTED = label `mdc-block-sensitive-interfaces` (restricted access). A label selector cannot OR, so both labels become columns (`<none>` when missing), grep keeps rows where either is `true`, and `column -t` re-aligns the rows that are left. |
| `kubectl get networkpolicies -n x-mdc-allowed -o yaml` | The same network policies as YAML. |
| `kubectl get ciliumnetworkpolicies -n x-mdc-allowed -o wide` | Cilium network policies, in case the isolation lands as one. |
| `kubectl logs -n x-mdc-allowed deploy/webapp --since=30s` | The heartbeat again - `ERROR` lines mean the isolation cut the pod's egress. |
| `kubectl get pods -n x-mdc-allowed -o wide --show-labels` | The webapp pods with all labels, including the response-action labels. |
| `kubectl get configmap panel-heartbeat -n x-mdc-allowed -o yaml` | The URL the heartbeat calls (from Git, filled in by Flux from the panel's hostname). |

## Accepted risk

| Command | What it does |
|---|---|
| `kubectl get pods -A -l risk.acceptance/state=accepted -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,EXPIRES:.metadata.labels['risk\.acceptance/expires'],CVES:.metadata.annotations['risk\.acceptance/cves']` | Pods labelled as risk-accepted, with expiry and the accepted CVEs. |
| `kubectl get pods -A -l risk.acceptance/state=accepted -o custom-columns=POD:.metadata.name,BY:.metadata.annotations['risk\.acceptance/approved-by'],EXPIRES:.metadata.labels['risk\.acceptance/expires'],EXEMPTION:.metadata.annotations['risk\.acceptance/defender-exemption']` | Approver, expiry and Defender exemption per risk-accepted pod. |
| `kubectl get pods -A -l risk.acceptance/state=accepted --sort-by=.metadata.labels['risk\.acceptance/expires'] -o custom-columns=EXPIRES:.metadata.labels['risk\.acceptance/expires'],NS:.metadata.namespace,POD:.metadata.name` | Risk acceptances sorted by expiry date. |
| `kubectl get deploy webapp -n x-mdc-allowed -o jsonpath={.spec.template.metadata.annotations}` | All annotations of the webapp's pod template (the full risk record). |
| `kubectl get deploy -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,ACCEPTED:.spec.template.metadata.labels['risk\.acceptance/state'],TICKET:.spec.template.metadata.annotations['risk\.acceptance/ticket']` | Every Deployment with its acceptance state and ticket. |
| `kubectl get pods -A -l '!risk.acceptance/state' -o custom-columns=NS:.metadata.namespace,POD:.metadata.name` | Pods that carry no `risk.acceptance/state` label at all. |

## Demo workloads

| Command | What it does |
|---|---|
| `kubectl get deploy,rs,pods -o wide -n x-mdc-blocked` | Everything in the gated namespace - the Deployment exists, its pods do not. |
| `kubectl get deploy,pods,svc -o wide -n x-mdc-allowed` | The admitted webapp: Deployment, pods and its LoadBalancer Service. |
| `kubectl get pods -o wide -n demo-ops` | The panel's kubectl runner and other ops pods. |
| `kubectl get jobs,pods -n demo-ops` | The Defender alert-simulation Job and its pod. |
| `kubectl logs -n demo-ops job/mdc-alert-triage --tail=200` | Output of the alert simulation scenarios. |
| `kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,IMAGE:.spec.containers[*].image` | Every pod with the image(s) it runs. |
| `kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,RUNASNONROOT:.spec.securityContext.runAsNonRoot` | Pods and whether they set `runAsNonRoot`. |
| `kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,PRIV:.spec.containers[*].securityContext.privileged` | Pods and whether any container runs privileged. |

## Manual deploys ("deploy it by hand")

Real pods, not dry runs: admission answers exactly as it would for an engineer.

| Command | What it does |
|---|---|
| `kubectl run manual-webapp-blocked -n x-mdc-blocked --restart=Never --labels=origin=manual --image=<acr>/aks-webapp:latest` | Deploy the vulnerable webapp as a real pod into the gated namespace - the image gate should deny it. |
| `kubectl run manual-webapp-allowed -n x-mdc-allowed --restart=Never --labels=origin=manual --image=<acr>/aks-webapp:latest` | The same image into the out-of-scope namespace - admitted. |
| `kubectl run manual-privileged-root -n x-mdc-blocked --restart=Never --labels=origin=manual --image=mcr.microsoft.com/azurelinux/base/core:3.0 --overrides='<privileged, runAsUser 0>'` | A privileged root pod (clean MCR image) into the gated namespace - the misconfiguration policy should deny it. Full `--overrides` JSON in the panel. |
| `kubectl run manual-restricted -n x-mdc-blocked --restart=Never --labels=origin=manual --image=<acr>/misconfig-alpine:latest --overrides='<non-root, no privilege escalation, read-only root, drop ALL>'` | The counter-beat: a restricted pod with a scanned, CVE-free image in the same gated namespace is admitted. `:latest` is set by the misconfiguration workflow. |
| `kubectl get pods -A -l origin=manual -o wide` | All manual-* pods (label `origin=manual`). |
| `kubectl delete pods -A -l origin=manual --ignore-not-found` | Delete every manual-* pod again. |

## Per-pod actions (right-click a pod)

| Command | What it does |
|---|---|
| `kubectl logs -n <ns> <pod> --all-containers --tail=200` | Last 200 log lines of every container. |
| `kubectl logs -n <ns> <pod> -c <container> --tail=200` | Logs of one container. |
| `kubectl logs -n <ns> <pod> -c <container> --tail=200 --previous` | Logs of the container's previous (crashed) instance. |
| `kubectl describe pod -n <ns> <pod>` | Pod details and its events. |
| `kubectl get pod -n <ns> <pod> -o yaml` | The pod as YAML. |
| `kubectl logs -n <ns> <pod> --since=2m` | Heartbeat log of that pod (x-mdc-allowed only). |

In `x-mdc-allowed` the menu also offers the binary drift, crypto mining and live-connections
commands from the isolation drill, aimed at the clicked pod.

## Blade buttons

| Command | What it does |
|---|---|
| `kubectl delete namespace <x-mdc-blocked\|x-mdc-allowed> --wait=false` | Reset a demo namespace; Flux recreates it and its workloads on the next sync. The runner may delete only these two. |
| `kubectl get events -n <ns> --field-selector reason=FailedCreate --sort-by=.lastTimestamp` | Admission denials of one namespace (from the denials blade). |
| `kubectl describe <kind> <name> -n <ns>` | Details of a denied object or a Flux resource (from the denials and GitOps blades). |

## Verify admission controls (button)

Reads plus three server-side dry runs; nothing is created.

| Command | What it checks |
|---|---|
| `kubectl get deploy defender-admission-controller -n mdc -o jsonpath={.status.readyReplicas}/{.spec.replicas}` | The admission controller is running (ready/desired). |
| `kubectl get validatingwebhookconfigurations -o name` | The image gate webhook is registered. |
| `kubectl get clusterroles -o name` | The Trusted Access roles Defender needs are bound. |
| `kubectl get securityartifactpolicies.defender.microsoft.com -A --no-headers` | Gated-deployment rules are synced. |
| `kubectl get validatingadmissionpolicybindings --no-headers -o custom-columns=NAME:.metadata.name,ACTIONS:.spec.validationActions` | Misconfiguration policies exist, and how many deny. |
| `kubectl get constraints --no-headers -o custom-columns=NAME:.metadata.name,ACTION:.spec.enforcementAction` | The Azure Policy add-on (Gatekeeper) is present, and its enforcement actions. |
| `kubectl run verify-gate -n x-mdc-blocked --restart=Never --dry-run=server --image=<acr>/aks-webapp:latest` | The image gate denies the vulnerable image (dry run). |
| `kubectl run verify-misconfig -n x-mdc-blocked --restart=Never --dry-run=server --image=<mcr image> --overrides=<privileged root>` | The misconfiguration policy denies a privileged root pod (dry run). |
| `kubectl run verify-restricted -n x-mdc-blocked --restart=Never --dry-run=server --image=<acr>/misconfig-alpine:latest --overrides=<restricted>` | A restricted pod with the scanned, CVE-free image is still admitted (dry run). |


## Restart all apps (button)

Spreads pods over the nodes again after a stop/start, when the node that was Ready first holds nearly everything. Covers `kube-system`, `gatekeeper-system`, `flux-system`, `demo-ops`, `x-mdc-allowed` and `x-mdc-blocked`. Only Deployment-owned pods are restarted; `mdc` (Defender's admission controller and sensor), the runner itself, DaemonSets and Jobs are left alone. Needs the runner's `kubectl-runner-operate` role (pod delete, cluster-wide).

| Command | What it does |
|---|---|
| `kubectl describe nodes` | CPU requested per node, before and after (from "Allocated resources"). |
| `kubectl get pods -n <ns> -o jsonpath=<name, owner kind, owner name, app label>` | Finds the Deployment-owned pods (owner = ReplicaSet) of each namespace. |
| `kubectl delete pod -n <ns> <pod> --wait=false` | Deletes one pod; its ReplicaSet recreates it and the scheduler places it on the node with room. |
| `kubectl wait -n <ns> rs/<replicaset> --timeout=60s --for=jsonpath={.status.readyReplicas}=<n>` | With several replicas: waits until the set is whole again before the next pod goes, so coredns, the webhooks and Gatekeeper never drop to zero. |
