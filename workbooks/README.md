# Workbooks

## `aks-cluster-fingerprint.workbook.json`

A per-cluster analyst view built entirely on **Defender XDR advanced hunting**
(`"queryType": "advancedHunting"`, 30-day native retention). No Log Analytics ingestion, no
workspace resource, nothing to deploy into the cluster.

It answers the question a SOC analyst actually has at 12:30: *what is this cluster, what is it
doing, what did the gate decide, who touched it, and what can it reach?*

64 panels. Every one of them was executed against the live advanced hunting API before shipping
(`POST /v1.0/security/runHuntingQuery`), not just schema-checked.

### Layout

The workbook is tabbed: the time range, cluster and namespace pickers stay at the top and apply
everywhere, and each section lives in its own tab.

| Tab | Panels (eager / on demand) |
| --- | --- |
| 🌐 Fleet | 5 / 2 |
| 🧭 Overview | 4 / 0 |
| 🚨 Alerts | 5 / 3 |
| 🚦 Admission | 3 / 0 |
| ⚙️ Runtime | 6 / 5 |
| 🌍 DNS egress | 5 / 7 |
| 🔑 Control plane | 5 / 4 |
| 🕸️ Exposure | 5 / 7 |
| 🐞 Vulnerabilities | 5 / 2 |

Mechanically that is a `type: 11` links item with `"style": "tabs"`, whose links write the
`selectedTab` parameter (`cellValue: "selectedTab"`, `linkTarget: "parameter"`, `subTarget:
"<tab>"`), plus one `type: 12` group per tab gated by

```json
"conditionalVisibility": { "parameterName": "selectedTab", "comparison": "isEqualTo", "value": "<tab>" }
```

The first tab needs no special casing - a tabs item selects its first link by default. Note that
`conditionalVisibilities` (plural) is **not** part of the workbook schema; use the singular form.
Groups load lazily, so only the visible tab runs its queries - which is also why the tabbed version
is much faster to open than the single-scroll one.

### Sections

| Section | Tables | What it tells you |
| --- | --- | --- |
| At a glance | `AlertInfo`, `AlertEvidence`, `CloudPolicyEnforcementEvents`, `CloudProcessEvents`, `CloudDnsEvents`, `CloudAuditEvents` | KPI tiles, plus a **telemetry heartbeat**: process, DNS, API and admission events per hour on one chart. A signal that flatlines is as interesting as one that spikes |
| Cross-signal | all cloud tables | **namespace risk rollup** (denies, shells, network tooling, external domains, exec, secret reads and denied API calls folded onto one key with an attention score) and **pods that ran a shell and then resolved external domains**. One signal is noise; two in the same pod is a lead |
| Alerts and incidents | `AlertInfo`, `AlertEvidence`, `SecurityIncident` | severity trend per day, **incidents opened vs closed per day (30d)**, open/closed state, hour-of-day alert profile, categories and techniques, detection sources, alert detail with entities and command lines |
| Admission control | `CloudPolicyEnforcementEvents` | allow/audit/deny over time, denies per namespace, every blocked or audited workload with the rule's reason |
| Namespace fingerprint | `CloudProcessEvents`, `CloudPolicyEnforcementEvents`, `CloudDnsEvents` | one row per namespace: pods, images, processes, accounts, denies, audits, domains; plus images and digests in use |
| Runtime behaviour | `CloudProcessEvents` | **behaviour profile per namespace** (shell / network tooling / recon / package install / cluster tooling, with a noisy-ratio), execution mix, **parent→child chains**, executions per day by category, workload churn, and process names new this week against the prior 23 days |
| Egress intent | `CloudDnsEvents` | **DNS profile per namespace** (external ratio, failure ratio), destination classes, **volume per day**, **cardinality and NXDOMAIN per day**, **domains first seen per day**, hour-of-day egress, top domains, **every external domain the cluster resolved** (with resolved IPs, resolver, record types, calling image and process) and the same list **rolled up by apex domain**, beaconing candidates, mining/tunnelling/dynamic-DNS patterns |
| Control plane | `CloudAuditEvents` | verb × resource, **who touched this cluster** (principal, verbs, denials, first/last seen), **sensitive operations** (exec, attach, port-forward, secrets, RBAC, admission-config changes), denied and failed calls as a recon signal, client user-agents, and all of it trended per day |
| Relationships and exposure risk | `ExposureGraphNodes`, `ExposureGraphEdges` | asset card, relationship vocabulary around this cluster, neighbours by type, **attack paths in** from internet-exposed assets, **attack paths out** to critical or sensitive assets |
| Identity reach — pod to Azure | `ExposureGraphNodes`, `ExposureGraphEdges` | the cluster's own identities classified (control plane, **kubelet/node pool**, add-ons, workload identity), what PaaS they can reach, and 1–2 hop paths to data services. This is the part that turns "a pod was compromised" into "a storage account was reachable" |
| Vulnerability load — aggregated | `ExposureGraphNodes`, `ExposureGraphEdges`, `CloudProcessEvents` | **runtime-filtered CVE view**: only images this cluster actually ran, rolled up by image risk score, by CVE blast radius and by namespace, with exploit availability and zero-day flags |

### The data source is a string, not a number

Every query item and **every query-backed parameter** carries its own `queryType`. For these
queries it must be the string:

```json
"queryType": "advancedHunting"
```

In the portal that is the **Advanced Hunting** entry in the query editor's *Data source* dropdown.
Numeric `queryType` values belong to Azure Monitor's own providers — `0` is Logs, `1` is **Azure
Resource Graph** — and `1` is what a workbook falls back to. A workbook pasted with `queryType: 1`
therefore runs Kusto against Resource Graph, where none of these tables exist.

The failure mode is nastier than a missing-table error, because the queries use
`union isfuzzy=true`: an unknown table is dropped instead of raising, the union collapses to an
empty schema, and the next line fails with

```
failed to resolve scalar expression named 'AzureResourceId'
filter expression should be boolean
```

which looks like a query bug. The unions here are seeded with an empty
`datatable(AzureResourceId: string)[]` so the column survives and a genuinely missing table yields
zero rows instead of that error — but the real fix is the data source. To switch every query and
parameter at once:

```bash
python3 workbooks/set-datasource.py advancedHunting
```

The Defender portal supplies the workspace context itself; it writes `crossComponentResources` into
an item when you change its data source by hand. If a query ever complains that it has no
workspace, re-run with `--workspace-param` to add a workspace picker and pin every query to it.

### Why advanced hunting and not the Sentinel workspace

Measured in a tenant with the Defender XDR connector enabled (2026-09-21):

| Table | Sentinel workspace | Advanced hunting |
| --- | --- | --- |
| `AlertInfo`, `AlertEvidence`, `SecurityIncident` | yes | yes |
| `CloudProcessEvents`, `CloudDnsEvents`, `CloudAuditEvents` | yes (carry both `TimeGenerated` and `Timestamp`) | yes |
| `CloudPolicyEnforcementEvents` | **no** | yes |
| `ExposureGraphNodes`, `ExposureGraphEdges` | **no** | yes |

A Log Analytics version of this workbook would lose admission control, exposure paths, identity
reach and the CVE rollup — about 20 of the 56 panels, including the ones the gated-deployment
story depends on.

### Three sources, and the gaps between them

The Fleet tab deliberately reads the same fleet from three places, because no single one is
complete:

| Source | Answers | Blind spot |
| --- | --- | --- |
| Advanced hunting telemetry | which clusters are *sending* data | a cluster with no sensor never appears |
| `ExposureGraphNodes` | which clusters Defender *knows*, and how they are configured | a current-state snapshot that keeps recently deleted clusters for a while |
| Azure Resource Graph (`queryType: 1`, `resourceType: microsoft.resourcegraph/resources`, `crossComponentResources: ["value::all"]`) | which clusters *exist right now*, node counts, versions | says nothing about what runs inside |

A workbook query cannot join across providers, so these stay separate panels — the **Merge** data
source can combine providers, but its JSON shape is in neither the published schema nor any
Microsoft template, so it is not used here. The *Active / Silent / Gone* flag is therefore derived
inside advanced hunting from `now() - max(Timestamp)`, which is the more useful definition anyway:
a cluster that stopped reporting is either deleted **or** has a broken sensor, and both need
someone to look.

Read the tab like this: in ARM but not in telemetry = unmonitored. In telemetry but not in ARM =
deleted. Node counts only ever come from ARM.

### Rate limits: why panels are behind a "Load more" button

Advanced hunting is rate-limited per tenant per minute. A tab that renders a dozen panels fires a
dozen queries in the same second and the portal returns **HTTP 429** for most of them — the tab
looks broken while the queries were merely throttled.

So every tab runs at most **4 panels automatically**; the rest sit in a nested group with

```json
"loadType": "explicit", "loadButtonText": "Load N more panels"
```

and run only when asked. Combined with lazy tab loading, opening the workbook costs 2 parameter
queries plus 4 panels rather than 65. If you still hit 429, wait a minute before pressing the load
buttons, and avoid switching tabs rapidly — each switch is a fresh burst of queries.

### Performance in a large tenant

Advanced hunting caps a query by time *and* by data scanned, so a 30-day window over
`CloudProcessEvents` in a big tenant is where this workbook would fall over first. Rules applied
throughout, worth keeping if you extend it:

- **Everything is aggregated.** No panel returns raw events. Detail grids end in `take`/`top`, and
  the ones that could grow without bound (CVE edges, process chains, audit principals) summarize
  first and cap second.
- **`materialize()` on any subquery used more than once.** Twelve panels re-referenced a `let`
  (the CVE `imageCves` expression five times, the kubelet identity set five times); without
  `materialize()` the engine re-runs the whole expression per reference.
- **Project early.** Kusto is columnar: a 30-day scan that touches `Timestamp` and
  `AzureResourceId` costs a fraction of one that touches ten columns. The fleet legs project down
  to the columns they aggregate before summarizing.
- **Cheap `dcount`.** Fleet counters use `dcount(x, 0)` — the fastest estimator, roughly 1.6%
  error. For "how many pods did this cluster run", that is the right trade; per-cluster panels keep
  the default accuracy.
- **Only the Fleet tab is pinned to 30 days**, and it is the one tab whose queries touch few
  columns. Every other tab follows the time picker, so the default 7 days is what actually runs.
- **Cut the edge set before the join, not after.** The CVE panels first build the list of image
  repos this cluster actually ran, then apply `| where TargetNodeName has_any (repoList)` to the
  `affecting` edges. Same results, 27-45s down to 6-11s per panel.
- **Tabs load lazily.** Opening the workbook runs one tab's queries, not 64 panels'.

If a panel still times out, narrow the time picker first and the namespace filter second — the
namespace parameter is pushed into the `where` clause of every runtime, DNS and admission query,
so it cuts the scan rather than filtering the result.

### Time filters: `{TimeRange:value}`, not `{TimeRange}`

Inside KQL a time parameter must be referenced as `{TimeRange:value}` (or `{TimeRange:query}`),
both of which expand to `> ago(7d)`. Bare `{TimeRange}` expands to the *label* — "Last 7 days" —
which is fine in Markdown and broken in a query.

### Parameters

`TimeRange` (1d–30d), `Cluster` and `Namespace` (multi-select, filters the runtime sections).

**The cluster picker is built from two independent sources**, because either one alone leaves the
workbook blank for somebody:

- the **Defender sensor** tables (`CloudProcessEvents`, `CloudDnsEvents`, `CloudAuditEvents`,
  `CloudPolicyEnforcementEvents`, last 30 days) — clusters actually sending runtime data
- the **exposure graph** (`ExposureGraphNodes`, label `microsoft.containerservice/managedclusters`)
  — every AKS cluster Defender knows about, sensor or not

Clusters with no runtime telemetry are labelled `(no sensor telemetry)` and sorted last. Their
posture, identity and CVE panels work; the runtime, DNS and admission panels stay empty — which is
itself the finding: Defender for Containers is not watching that cluster.

The picker returns `value`, `label`, `selected` in that order, and pre-selects the first
sensor-backed cluster, so the workbook has data the moment it opens. Without that third column a
dropdown opens with **nothing selected** and every panel renders empty — that is the single most
common reason a pasted workbook "does not work".

Two details worth knowing if you edit the picker:

- A cluster resource ID has exactly **9 path segments**. `EntityIds` on a graph node also carries
  the cluster's *child* resources (role assignments), so without the segment check the dropdown
  fills with GUIDs.
- The graph returns resource IDs **lowercased**, the runtime tables return them in ARM casing. The
  picker normalises to lowercase and every panel compares with `=~` or `has`, both
  case-insensitive, so either spelling resolves the same cluster.

### Prerequisites

- Defender for Containers with the **sensor** deployed — no sensor, no `CloudProcessEvents` or `CloudDnsEvents`
- **Gated deployment** enabled — otherwise `CloudPolicyEnforcementEvents` is empty
- Defender for Cloud connected to the Defender portal (this is what populates the cloud tables)
- **Security Exposure Management** for `ExposureGraphNodes` / `ExposureGraphEdges`
- **Sentinel onboarded to the Defender portal** for `SecurityIncident` — this is the only source
  of open/closed state, because `AlertInfo` has no status column

### Deploy

Defender portal → Microsoft Sentinel → Threat management → **Workbooks** → Add workbook → Edit →
Advanced Editor (`</>`) → paste the JSON → Save.

### Known caveats

- `CloudPolicyEnforcementEvents` is in preview; columns may change.
- **`CloudAuditEvents` has mixed casing.** The column is `AzureResourceId` (there is no
  `ResourceId`), `DataSource` reads `Azure Kubernetes Service` (not `Kubernetes Audit`), and inside
  `RawEventData` the top-level keys are PascalCase (`Verb`, `User`, `ObjectRef`, `ResponseStatus`)
  while their sub-keys are camelCase (`User.username`, `ObjectRef.resource`,
  `ResponseStatus.code`). KQL is case-sensitive on dynamic properties, so the wrong spelling
  silently returns empty strings rather than an error. Control-plane events from controllers often
  carry no `ObjectRef.namespace`/`name` at all.
- `AttackTechniques` is empty for most Defender for Cloud container alerts, so the technique panel
  falls back to `Category`.
- The "new process names" and "domains first seen" panels are baselines, not top-N lists. The
  first bucket of a first-seen chart always spikes, because on day one everything is new — read
  the days after it.
- Alerts are bound to a cluster through `AlertEvidence.ResourceID` / `CloudResource`. An alert
  whose evidence carries neither will not appear under that cluster.
- The exposure-graph panels are **not** time-filtered: the graph is a current-state snapshot, not an
  event stream. Everything else honours the time picker.
- The CVE section is deliberately joined against runtime. `Cve -[affecting]-> container-image` is
  tens of thousands of edges tenant-wide; intersecting it with the images this cluster actually
  executed is what makes it readable — and is also the honest answer to "which of these CVEs
  matter to me".
- Image matching reduces both sides to `registry/repo`: graph nodes are `repo@sha256:…`, runtime
  reports `repo:tag`. Digest-level matching would be stricter but misses every retagged image.
- **Path panels do not use `make-graph`.** `make-graph` builds the entire tenant exposure graph
  before `graph-match` filters anything: measured on a tenant with ONE cluster, the two path
  panels took 120s and 136s, and the identity-to-data panel did not finish inside 180s. They are
  now chains of seeded hops instead -
  `ExposureGraphEdges | where TargetNodeId in ((previousHop | project SourceNodeId))` - so each
  step filters the edge scan against a small node set. Same reach (1..3 hops), same output:
  0.3s, 1.9s and 15.1s. If you extend these, keep the seeded shape and never reintroduce
  `make-graph` over the unfiltered edge table.
- Property keys under `NodeProperties.rawData` vary by source (`exposedToInternet` and
  `IsInternetFacing` both appear, hence the `or`). Run
  `ExposureGraphNodes | where ... | project-keep NodeProperties | take 1` to see what your tenant
  actually populates before tuning these.
- Identity panels find the cluster's identities by matching the cluster resource ID and the
  `MC_<rg>_<cluster>_<region>` node resource group inside `rawData.alternativeNames`. A cluster with
  a custom node resource group name still matches on the cluster ID, but check the classification
  column before trusting the kubelet row.
- The namespace rollup folds four tables with `union` + `summarize`, not `join kind=fullouter`. A full outer join
  returns **empty strings** for missing string keys, not nulls, so `coalesce` keeps them and the same namespace
  splits into phantom rows. Events with no namespace are labelled `cluster-scoped` rather than dropped.
- The external-domain list drops `*.cluster.local`, `*.svc` and single-label names: in-cluster service
  discovery is not egress. Resolved IPs come from `AdditionalFields.addresses`, a JSON **string** inside
  the dynamic column, so it needs `todynamic(tostring(...))`; lookups that got no answer are kept and
  marked `(no answer)` rather than dropped by `mv-expand`, because an unanswered lookup is the
  interesting one. The cluster's DNS search path appends suffixes like
  `<name>.<id>.<region>.internal.cloudapp.net`, which is why the same destination appears twice in the
  full list and once in the apex rollup.
- Everything is scoped to one cluster on purpose. For a fleet view, drop the `ClusterId` filter
  and summarize by `AzureResourceId`.
