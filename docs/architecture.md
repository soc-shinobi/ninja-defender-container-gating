# Demo lab architecture

Central code-to-runtime container and CI/CD security with Microsoft Defender for Cloud.
Focus: shift-left plus defense in depth, left to right. No WAF, no App Gateway, no ingress edge security. That is a separate topic.

Verified against Microsoft Learn on 2026-09-18.

## The idea in one line

Two teams build the same vulnerable app. One adopted shift-left, one did not. Every layer from laptop to SOC catches what the layer before it missed, and none of it touches the app owner's pipeline. The Container App `<namePrefix>-app`, built from ACR repository `aca-webapp`, is the lab's cockpit. The AKS workload is a separate, small app (`app/aks-webapp`, ACR repository `aks-webapp`, Kubernetes Deployment `webapp`): a public dashboard of the synthetic blob data, read via workload identity, with the same planted vulnerable packages.

## ASCII architecture

```
        SHIFT-LEFT ────────────────────────────────────────────────────────────► SHIFT-RIGHT
        (app team owns)                                                        (security owns)

 L0 DEVELOPER      L1 REPOSITORY        L2 PIPELINE         L3 REGISTRY      L4 ADMISSION
 ┌────────────┐    ┌───────────────┐    ┌──────────────┐    ┌───────────┐    ┌─────────────┐
 │ gitleaks   │    │ Team Atlas    │    │ atlas-ci     │    │    ACR    │    │ AKS gating  │
 │ pre-commit │───►│ GHAS push     │───►│ defender     │───►│ scan on   │───►│ admission   │
 │ (skippable)│    │ protection    │    │  scan fs     │    │ push  +   │    │ webhook     │
 └─────┬──────┘    ├───────────────┤    │  scan image  │    │ SIGNED    │    │ deny/audit  │
       │           │ Team Ship-It  │    │  (BREAKS)    │    │ findings  │    │  per TIER   │
  --no-verify      │ no scanning   │───►├──────────────┤───►│ artifact  │    └──────┬──────┘
       ▼           └───────┬───────┘    │ shipit-build │    │ on digest │           │
   bypassed                │            │ build+push   │    └─────┬─────┘     force_push /
                           │            │ force_push ⚠ │          │          skip_scan still
                           │            └──────┬───────┘          │          land here ──┐
                           ▼                   ▼                  ▼                      ▼
 ┌──────────────────────────────────────────────────────────────────────────────────────────┐
 │                  MICROSOFT DEFENDER FOR CLOUD — central control plane                     │
 │  GitHub connector      Defender CSPM        Defender for Containers     Defender for AI   │
 │  agentless code scan   security graph       registry VA + SIGNED VA     model-call alerts │
 │  IaC/deps/SBOM         attack paths         gated deployment rules      (optional)        │
 │  DevOps posture        code-to-runtime      binary drift policy                           │
 │  NO pipeline edits     blast radius         runtime threat + sensor                       │
 └──────────────────────────────────────────────────────────────────────────────────────────┘
        │                                                          ▲
        │ finding ─► GitHub issue (SDLC context) ─► PR             │ "resolved" syncs back
        ▼                                                          │ when the PR merges
 ┌──────────────────────────────┐                                  │
 │ fix ONCE at the source ──────┼──────────────────────────────────┘
 └──────────────────────────────┘

 WORKLOAD PLANE
 ┌───────────────────────────────────┐        ┌──────────────────────────────────────────────┐
 │ Azure Container Apps              │        │ AKS  (2 nodes, ephemeral OS disk, Cilium)     │
 │ ┌───────────────────────────────┐ │        │                                               │
 │ │ <namePrefix>-app (aca-webapp) │ │        │  ns x-mdc-blocked  in gate scope → DENIED       │
 │ │  • cluster / nodes / namespaces│ │  K8s   │    webapp (hero digest)                       │
 │ │  • pods, images, restarts     │ │  API   │  ns x-mdc-allowed → Deployment/webapp + LB       │
 │ │  • pod logs                   │─┼───────►│    image: <acr>/aks-webapp:<tag>              │
 │ │  • kubectl console            │ │ (read) │  ns demo-ops     runner/control plane         │
 │ │  • alert-sim scenario picker  │ │        │   ┌────────────────────────────────────────┐  │
 │ │  • optional Foundry chat      │ │  exec  │   │ kubectl-runner pod                     │  │
 │ │                               │─┼───────►│   │  NO Service · NO ingress               │  │
 │ │ Basic auth or Entra EasyAuth  │ │ pods/  │   │  SA: read cluster-wide, write in demo  │  │
 │ │ user-assigned identity        │ │ exec   │   └────────────────────────────────────────┘  │
 │ └───────────────────────────────┘ │        │   ┌────────────────────────────────────────┐  │
 │  Azure RBAC for Kubernetes:       │ create │   │ Job: mdc-alert-triage (33 scenarios)   │  │
 │   Reader  @ cluster  (read all)   │  Job   │   │  run / RE-RUN from the panel, ttl 15m  │  │
 │   Writer  @ ns demo-ops (exec)    │───────►│   └────────────────────────────────────────┘  │
 └───────────────┬───────────────────┘        │   webapp → ACA /healthz heartbeat              │
                 │ managed identity           │   Defender sensor + Security Gating           │
                 ▼                            │   Flux GitOps reconciles app/k8s              │
 ┌───────────────────────────────────┐        └──────────────────────────────────────────────┘
 │ Azure AI Foundry  (OPTIONAL)      │
 │  model inference → Defender for AI│        NOTE: every panel action goes through the AKS
 │  published agent → Agent 365      │        API server, so it is Entra-authenticated, Azure-
 └───────────────────────────────────┘        RBAC-authorized and AUDITED in CloudAuditEvents.
                                              x-mdc-allowed/webapp also reads Blob
                                              sensitive-data/customers.json through SA
                                              aks-webapp + workload identity (no key).
                                              ACA itself has NO Defender runtime protection:
                                              it is covered by ACR scanning + CSPM posture.
```

## Deployed names and data flows

| Purpose | Deployed name |
| --- | --- |
| ACA control panel | Container App `<namePrefix>-app`, container `app`, image `<acr>/aca-webapp:<tag>` |
| AKS cluster | `<namePrefix>-aks` |
| Admission-blocked workload | `x-mdc-blocked/Deployment/webapp`, image `<acr>/aks-webapp:<tag>` |
| Public allowed workload | `x-mdc-allowed/Deployment/webapp` and `Service/webapp` (`LoadBalancer`), image `<acr>/aks-webapp:<tag>` |
| AKS workload identity | user-assigned identity `<namePrefix>-aks-webapp-id`, ServiceAccount `x-mdc-allowed/aks-webapp` |
| Sensitive demo data | storage account `st<namePrefix><unique>`, private container `sensitive-data`, blob `customers.json` |
| Operations runner | `demo-ops/Pod/kubectl-runner` |
| Alert simulation | `demo-ops/Job/mdc-alert-triage` |

The browser reaches `x-mdc-allowed/Service/webapp` through its public LoadBalancer. That pod calls
`https://<namePrefix>-app.../healthz` for the ACA heartbeat and uses its federated workload
identity to read `sensitive-data/customers.json`. The page exposes both connection states and
renders only the deliberately synthetic records from `demo-data/fake-sensitive-data.json`.

## Coverage matrix (what protects what)

| Layer | Control | Plan / component | Touches app pipeline? | Live or pre-seeded |
| --- | --- | --- | --- | --- |
| 0 Developer | gitleaks pre-commit | local git hook (not Defender) | yes, opt-in | live |
| 1 Repository | push protection, branch policy | GitHub native | no (org level) | live |
| 1 Repository | secrets / code / dep / IaC findings | Defender agentless code scanning | no | pre-seeded (daily) |
| 1 Repository | pipeline & connection posture | Defender DevOps posture | no | pre-seeded (8h) |
| 2 Pipeline | image scan + break | Defender for Cloud CLI | yes, opt-in | live (Atlas) |
| 3 Registry | image VA + signed findings artifact | Defender for Containers, Registry access + Security findings | no | pre-seeded |
| 3 Registry | blast radius, attack path, owners | Defender CSPM cloud security graph | no | pre-seeded |
| 4 Admission | deny vulnerable image, incl. one force-pushed past the pipeline | Defender for Containers gating (admission webhook), owned by security | no | live |
| 4 Admission | GitOps sync denied by the gate (Flux) | AKS GitOps extension (`microsoft.flux`), pure Bicep | no | live |
| 4 Admission | registry-agnostic runtime VA of bypass | Defender for Containers / CSPM | no | pre-seeded |
| 5 Runtime | drift, threat detection, malware | Defender sensor | no | live |
| 5 Runtime | model-call alerts (only if `deployFoundry=true`) | Defender for AI Services | no | live |
| 5 Runtime | control-panel exec is itself audited | CloudAuditEvents | no | live |
| 5 Runtime | AKS app reads fake confidential Blob data | workload identity + container-scoped Blob Data Reader | no | live |
| 5 Runtime | 33-scenario alert simulation, run/re-run from the panel | `app/mdc-alert-simulation` Job in `demo-ops` | no | live |
| 6 SOC | terminate / isolate / restrict pod | Defender XDR (Preview) | no | live |
| Loop | issue -> PR -> resolved sync | Defender + GitHub | no | pre-seeded |

## Exception approval

The lab uses a public Logic App trigger protected by SAS, HMAC, GitHub Actions IP ranges, and
server-side fact verification. Production should put APIM with GitHub OIDC in front; the
strongest variant also uses a Logic App Standard private endpoint and an ephemeral VNet runner.
The Logic App remains the Teams approval and GitHub write-back orchestrator. See
[`exception-approval-playbook.md`](exception-approval-playbook.md) for the full design.

## Key IaC boundaries (what Bicep can and cannot do)

Deployable in Bicep: resource group, Log Analytics, ACR, ACA, AKS, identities and federation,
Blob Storage and RBAC, optional Foundry, Flux GitOps, role assignments, and Defender plans.

Post-deploy/manual: gated-deployment and drift policies, Defender GitHub OAuth connector,
Foundry agent publication, local gitleaks hook, sample workflows, and branch protection.

## AKS sizing decision

- Smallest practical node that supports an ephemeral (non-persistent) OS disk and still runs the Defender sensor daemonset: `Standard_D2ds_v5` (2 vCPU, 8 GiB RAM, ~75 GiB temp disk). The temp disk is large enough to host a 30 GiB ephemeral OS disk.
- `osDiskType: 'Ephemeral'` = non-persistent OS disk, wiped on node reimage. Cheaper and matches the demo-lab intent.
- 2 nodes by default, `aksNodeCount: 2`. Autoscale is off. The second small node leaves enough room for the Defender sensor and gating components beside the AKS system pods.
- Network: Azure CNI Overlay + Cilium data plane + Cilium network policy. The network policy engine is what makes the XDR **isolate pod** action work. Without it, only **terminate** works.
- OIDC issuer and workload identity are on, required by gated deployment.

If `Standard_D2ds_v5` is unavailable in the target region, `Standard_D2s_v3` works but pins the ephemeral OS disk to the smaller cache disk; the parameter file notes the fallback.
