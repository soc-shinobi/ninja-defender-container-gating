"""Defender demo: AKS control panel (and deliberately vulnerable sample app).

PRIMARY JOB: manage the demo AKS cluster from a browser - cluster overview, nodes,
namespaces, running pods, pod logs, and a kubectl console - plus the scripted attack
simulations the talk uses.

HOW IT REACHES THE CLUSTER
  Structured views  -> the Kubernetes API directly, with an Entra token from this app's
                       managed identity. Authorization is Azure RBAC:
                         AKS RBAC Reader  at cluster scope        (read everything)
                         AKS RBAC Writer  scoped to /namespaces/demo-ops  (exec)
  kubectl console   -> `exec` into the kubectl-runner pod in demo-ops (app/k8s/30-kubectl-
                       runner.yaml) through the API server's pods/exec subresource, output
                       streamed back to the browser.

WHY exec INTO A POD instead of exposing one
  The runner has no Service, no ingress, no public endpoint. Everything goes through the AKS
  API server, so it is authenticated by Entra, authorized by Azure RBAC, and AUDITED - every
  exec lands in CloudAuditEvents. Which is the talking point: from the cluster's side a
  legitimate control plane and an attacker look identical.

SAFETY
  KUBECTL_MODE controls the console:
    readonly (default) - get/describe/logs/top/events/version/api-resources only
    demo               - adds the scripted simulation commands
    unrestricted       - anything (lab only; this is remote code execution by design)
  Always keep Entra auth on the Container App. Never expose this without it.

Foundry chat is OPTIONAL and off unless FOUNDRY_ENDPOINT is set.
"""
import base64
import hashlib
import hmac
import itertools
import json
import os
import re
import shlex
import subprocess  # noqa: F401  (kept for local/offline mode)
from collections import deque
from flask import Flask, request, jsonify, render_template_string, Response, stream_with_context

app = Flask(__name__)

# ---- config ---------------------------------------------------------------
AKS_FQDN = os.environ.get("AKS_API_FQDN", "")          # e.g. defdemo-aks-xxxx.hcp.<region>.azmk8s.io
AKS_NAME = os.environ.get("AKS_NAME", "")
RUNNER_NS = os.environ.get("RUNNER_NAMESPACE", "demo-ops")
RUNNER_SELECTOR = os.environ.get("RUNNER_SELECTOR", "app=kubectl-runner")
KUBECTL_MODE = os.environ.get("KUBECTL_MODE", "readonly").lower()
# Well-known AKS Entra server application ID; the token audience for the AKS API server.
AKS_AAD_SERVER = os.environ.get("AKS_AAD_SERVER_APP_ID", "6dae42f8-4368-4678-94ff-3960e28e3630")
# ---- who may open this panel --------------------------------------------
# Two mutually exclusive modes, chosen at deploy time:
#   entra - Container Apps EasyAuth sits in front, scoped to assigned users
#           (make auth PANEL_ENTRA_USER=<upn>). Nothing to enforce in here.
#   basic - no Entra user was given, so the app enforces HTTP Basic itself with a
#           RANDOM password generated at deploy time and kept as a Container App
#           secret. Lab fallback: no MFA, no Conditional Access - but never open.
BASIC_USER = os.environ.get("BASIC_AUTH_USER", "")
BASIC_PASSWORD = os.environ.get("BASIC_AUTH_PASSWORD", "")
BASIC_ON = bool(BASIC_PASSWORD)
OPEN_PATHS = {"/healthz"}       # probe only; carries no cluster data

# ---- machine access to the REST API -------------------------------------
# The browser UI authenticates with Basic (or EasyAuth) and the fetch() calls inherit it.
# Scripts and agents instead send a key in a header. The key lives as a Container App
# secret, exactly like the password: empty here means key auth is simply not available,
# never that /api is open.
API_KEY = os.environ.get("PANEL_API_KEY", "")
API_KEY_HEADER = os.environ.get("PANEL_API_KEY_HEADER", "X-API-Key")
API_PREFIX = "/api/"

# The AKS API server presents a certificate signed by the CLUSTER's own CA, not a public
# one, so the system trust store cannot verify it. The CA comes from the cluster's
# kubeconfig (listClusterUserCredential), which the app identity may read because it holds
# the Azure Kubernetes Service Cluster User role. AKS_CA_CERT_B64 short-circuits the call.
AKS_RESOURCE_ID = os.environ.get("AKS_RESOURCE_ID", "")
AKS_CA_CERT_B64 = os.environ.get("AKS_CA_CERT_B64", "")
ARM_ENDPOINT = os.environ.get("ARM_ENDPOINT", "https://management.azure.com")
AKS_ARM_API_VERSION = os.environ.get("AKS_ARM_API_VERSION", "2024-05-01")
CA_CERT_PATH = os.environ.get("AKS_CA_CERT_PATH", "/tmp/aks-cluster-ca.crt")
_ca_file_cached = None

FOUNDRY_ENDPOINT = os.environ.get("FOUNDRY_ENDPOINT", "")   # optional
AI_MODEL_NAME = os.environ.get("AI_MODEL_NAME", "gpt-4o-mini")

# The public AKS copy uses workload identity to retrieve synthetic confidential data.
# The ACA control-panel copy has none of these variables and reports the connection disabled.
STORAGE_ACCOUNT_URL = os.environ.get("STORAGE_ACCOUNT_URL", "")
STORAGE_CONTAINER = os.environ.get("STORAGE_CONTAINER", "sensitive-data")
STORAGE_BLOB = os.environ.get("STORAGE_BLOB", "customers.json")
STORAGE_POLL_SECONDS = int(os.environ.get("STORAGE_POLL_SECONDS", "30"))
_connections = {
    "heartbeat": {"configured": False, "status": "disabled", "target": ""},
    "blob": {"configured": bool(STORAGE_ACCOUNT_URL), "status": "disabled",
             "target": (f"{STORAGE_CONTAINER}/{STORAGE_BLOB}" if STORAGE_ACCOUNT_URL else ""),
             "classification": "", "records": [], "bytes": 0, "sha256": "",
             "last_checked": "", "error": ""},
}

# Defender for Containers alert-triage image (app/mdc-alert-simulation). Benign by design:
# no malware, no real credential dumping, no malicious infrastructure. Run in a lab cluster
# only. It is run-to-completion, so the natural primitive is a Job - which also gives us a
# clean "re-run": delete the Job, create it again.
ALERT_SIM_IMAGE = os.environ.get("ALERT_SIM_IMAGE", "")     # <acr>/mdc-alert-triage:latest
SIM_JOB = os.environ.get("ALERT_SIM_JOB_NAME", "mdc-alert-triage")
SIM_NS = os.environ.get("ALERT_SIM_NAMESPACE", RUNNER_NS)   # demo-ops (sandbox tier)
SIM_DEFAULTS = {
    "CANARY_DOMAIN": os.environ.get("CANARY_DOMAIN", "canary.invalid"),
    "SUSPICIOUS_DNS": os.environ.get("SUSPICIOUS_DNS", "mdc-eicar.alerts.security.azure.com"),
    "SUSPICIOUS_IP": os.environ.get("SUSPICIOUS_IP", "abcdefghijklmnop.onion.to"),
    "MINING_POOL_DOMAIN": os.environ.get("MINING_POOL_DOMAIN", "poolmining.org"),
}
# Scenario catalogue (must match mdc-alert-runner.sh). Grouped for the UI.
SCENARIO_GROUPS = {
    "quick wins (start here)": ["binary_drift", "network_scan", "miner_process",
                                "mining_pool_access", "reverse_shell_pattern"],
    "execution / evasion": ["base64_exec", "download_chmod_exec", "php_execution",
                            "chattr_change", "timestamp_modify", "log_tamper",
                            "history_impair"],
    "discovery / recon": ["secret_recon", "sensitive_file_access", "bash_profile_access",
                          "bash_history_access", "metadata_access", "path_traversal",
                          "serviceaccount_token_access", "kubelet_kubeconfig_access",
                          "k8s_api_request"],
    "network": ["netcat_activity", "proxy_tool", "suspicious_dns", "suspicious_ip",
                "oast_domain"],
    "privilege / persistence": ["privileged_command", "account_sudo", "namespace_create",
                                "cron_ops", "sshd_container", "miner_process_kill"],
    "other": ["malware_test_placeholder"],
}
SCENARIOS = sorted({x for g in SCENARIO_GROUPS.values() for x in g})

READONLY_VERBS = {"get", "describe", "logs", "top", "events", "version", "api-resources",
                  "explain", "cluster-info"}

# Registry the demo images live in, so the gate-test commands are copy-paste ready.
ACR_LOGIN_SERVER = ALERT_SIM_IMAGE.split("/")[0] if "/" in ALERT_SIM_IMAGE else ""
DEFENDER_NS = os.environ.get("DEFENDER_NAMESPACE", "mdc")

# Second drill trigger next to binary drift, which does not fire reliably: contact a crypto
# mining pool from the x-mdc-allowed webapp. curl when the image has it (app/aks-webapp installs
# it), python3 otherwise. Any HTTP status counts as an answer: the pool sits behind a CDN that
# returns 403 to scripted clients, and the DNS lookup plus the connection are what the sensor
# sees. python3 uses a bare OpenerDirector so a 4xx comes back as a status instead of a
# traceback. No single quotes in here: the whole script is wrapped in sh -c '...'.
MINING_POOL = SIM_DEFAULTS["MINING_POOL_DOMAIN"]
MINING_DRILL_SH = (
    f"echo resolving {MINING_POOL}; getent hosts {MINING_POOL} || echo no DNS answer; "
    f"if command -v curl >/dev/null; then client=curl; "
    f"code=$(curl -s -m 5 -o /dev/null -w %{{http_code}} http://{MINING_POOL}); "
    f"else client=python3; "
    f'code=$(python3 -c "import sys, urllib.request as u; o = u.OpenerDirector(); '
    f'o.add_handler(u.HTTPHandler()); print(o.open(sys.argv[1], timeout=5).status)" '
    f"http://{MINING_POOL} 2>/dev/null); fi; "
    f'if [ -n "$code" ] && [ "$code" != 000 ]; then '
    f'echo "pool answered via $client: HTTP $code (connection made)"; '
    f'else echo "no answer via $client (the DNS lookup above still counts)"; fi'
)
MINING_DRILL_CMD = f"kubectl exec -n x-mdc-allowed deploy/webapp -- sh -c '{MINING_DRILL_SH}'"

# Live TCP connections of the x-mdc-allowed webapp, like `netstat -antp`. The image ships no
# netstat, ss or lsof, so python3 reads the kernel tables (/proc/net/tcp, tcp6) and maps each
# socket inode to its process through /proc/<pid>/fd. One line, no double quotes and no |, so
# it survives the console input, the panel's pipe parser and the onclick attribute unchanged.
CONNS_PY = (
    "import glob, os, socket as s, struct as t; "
    "ST = dict(zip('01 02 03 04 05 06 07 08 09 0A 0B'.split(), 'ESTABLISHED SYN_SENT SYN_RECV FIN_WAIT1 FIN_WAIT2 TIME_WAIT CLOSE CLOSE_WAIT LAST_ACK LISTEN CLOSING'.split())); "
    "own = {}; "
    "[own.setdefault(os.readlink(f)[8:-1], f.split('/')[2]) for f in glob.glob('/proc/[0-9]*/fd/*') if os.path.islink(f) and os.readlink(f).startswith('socket:')]; "
    "prog = lambda p: p + '/' + open('/proc/' + p + '/comm').read().strip() if p else '-'; "
    "a4 = lambda h: s.inet_ntoa(t.pack('<I', int(h, 16))); "
    "a6 = lambda h: s.inet_ntop(s.AF_INET6, b''.join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))); "
    "ep = lambda x, f: f(x.split(':')[0]) + ':' + str(int(x.split(':')[1], 16)); "
    "rows = [(pr, ep(c[1], f), ep(c[2], f), ST.get(c[3], c[3]), prog(own.get(c[9], ''))) for pr, fn, f in (('tcp', '/proc/net/tcp', a4), ('tcp6', '/proc/net/tcp6', a6)) if os.path.exists(fn) for c in [l.split() for l in open(fn).readlines()[1:]]]; "
    "[print('%-5s %-28s %-28s %-12s %s' % r) for r in [('Proto', 'Local Address', 'Foreign Address', 'State', 'PID/Program')] + sorted(rows, key=lambda r: (r[3] != 'LISTEN', r[3], r[1]))]; "
    "print(); "
    "print('%d tcp socket(s), %d established, %d listening' % (len(rows), sum(r[3] == 'ESTABLISHED' for r in rows), sum(r[3] == 'LISTEN' for r in rows)))"
)
CONNS_CMD = shlex.join(["kubectl", "exec", "-n", "x-mdc-allowed", "deploy/webapp", "--",
                        "python3", "-c", CONNS_PY])


def command_library():
    """Curated kubectl commands, grouped for the console picker and served at /api/commands.

    NO SHELL is involved: the panel splits the string with shlex and execs the argv in the
    runner pod, so a pipe into grep would be passed to kubectl as an argument. Everything
    here therefore filters with kubectl's own flags (-o, --field-selector, -l)."""
    acr = ACR_LOGIN_SERVER or "<acr>.azurecr.io"
    return [
        ("cluster", [
            ("nodes (wide)", "kubectl get nodes -o wide"),
            ("namespaces", "kubectl get namespaces"),
            ("all pods (wide)", "kubectl get pods -A -o wide"),
            ("pods not running", "kubectl get pods -A --field-selector=status.phase!=Running"),
            ("node resource usage", "kubectl top nodes"),
            ("pod resource usage", "kubectl top pods -A"),
            ("recent events", "kubectl get events -A --sort-by=.lastTimestamp"),
            ("what the API serves", "kubectl api-resources --verbs=list -o name"),
        ]),
        ("defender sensor", [
            ("sensor pods", f"kubectl get pods -n {DEFENDER_NS} -o wide"),
            ("sensor workloads", f"kubectl get daemonset,deployment -n {DEFENDER_NS}"),
            ("admission controller logs", f"kubectl logs -n {DEFENDER_NS} deploy/defender-admission-controller --tail=100"),
            ("collector logs", f"kubectl logs -n {DEFENDER_NS} ds/microsoft-defender-collector-ds --tail=100 --all-containers"),
            ("publisher logs", f"kubectl logs -n {DEFENDER_NS} ds/microsoft-defender-publisher-ds --tail=100"),
            ("sensor restarts / crashes", f"kubectl get pods -n {DEFENDER_NS} -o wide --sort-by=.status.containerStatuses[0].restartCount"),
            ("sensor events", f"kubectl get events -n {DEFENDER_NS} --sort-by=.lastTimestamp"),
        ]),
        ("misconfiguration policies (VAP)", [
            ("admission policies", "kubectl get validatingadmissionpolicies"),
            ("policy bindings (audit vs deny)", "kubectl get validatingadmissionpolicybindings"),
            ("bindings with their action", "kubectl get validatingadmissionpolicybindings -o custom-columns=NAME:.metadata.name,POLICY:.spec.policyName,ACTIONS:.spec.validationActions"),
            ("one policy in full (CEL)", "kubectl get validatingadmissionpolicies -o yaml"),
            ("Defender policy templates", "kubectl get policytemplates.defender.microsoft.com"),
            ("Defender policies", "kubectl get policies.defender.microsoft.com -A"),
            ("Defender runtime policies", "kubectl get runtimepolicies.defender.microsoft.com -A"),
            ("Defender CRDs", "kubectl get crd -o name"),
        ]),
        ("gated deployment (image gate)", [
            ("admission webhooks", "kubectl get validatingwebhookconfigurations"),
            ("the Defender image gate webhook", f"kubectl describe validatingwebhookconfiguration defender-admission-controller.{DEFENDER_NS}.svc"),
            ("security artifact policies", "kubectl get securityartifactpolicies.defender.microsoft.com -A"),
            ("admission controller RBAC", "kubectl get clusterrole defender-admission-controller-cluster-role -o yaml"),
            ("admission controller binding", "kubectl get clusterrolebinding defender-admission-controller-cluster-role-binding -o yaml"),
            ("resource role (gating)", "kubectl get clusterrole defender-admission-controller-resource-cluster-role -o yaml"),
            ("resource binding (gating)", "kubectl get clusterrolebinding defender-admission-controller-cluster-resource-role-binding -o yaml"),
            ("artifact policies (full JSON)", "kubectl get securityartifactpolicies.defender.microsoft.com -A -o json"),
            ("webhook endpoints", "kubectl get validatingwebhookconfigurations -o custom-columns=NAME:.metadata.name,SERVICE:.webhooks[*].clientConfig.service.name,NS:.webhooks[*].clientConfig.service.namespace,PATH:.webhooks[*].clientConfig.service.path"),
            ("TEST: blocked namespace", f"kubectl run gate-test --image={acr}/aca-webapp:latest -n x-mdc-blocked --restart=Never"),
            ("TEST: allowed namespace", f"kubectl run gate-test --image={acr}/aca-webapp:latest -n x-mdc-allowed --restart=Never"),
            ("clean up the allowed test", "kubectl delete pod gate-test -n x-mdc-allowed --ignore-not-found"),
        ]),
        ("flux gitops", [
            ("kustomizations", "kubectl get kustomizations.kustomize.toolkit.fluxcd.io -A"),
            ("git sources", "kubectl get gitrepositories.source.toolkit.fluxcd.io -A"),
            ("why the blocked Kustomization failed",
             f"kubectl describe kustomizations.kustomize.toolkit.fluxcd.io -n {FLUX_NS} {FLUX_CONFIG}-blocked"),
            ("admission denials (FailedCreate events)",
             "kubectl get events -A --field-selector reason=FailedCreate --sort-by=.lastTimestamp"),
            ("ReplicaSets the gate refused", "kubectl describe rs -n x-mdc-blocked"),
            ("flux controller events", f"kubectl get events -n {FLUX_NS} --sort-by=.lastTimestamp"),
            ("kustomize-controller logs", f"kubectl logs -n {FLUX_NS} deploy/kustomize-controller --tail=100"),
            ("source-controller logs", f"kubectl logs -n {FLUX_NS} deploy/source-controller --tail=100"),
            ("notification alerts and providers",
             f"kubectl get alerts.notification.toolkit.fluxcd.io,providers.notification.toolkit.fluxcd.io -n {FLUX_NS}"),
        ]),
        # The drill, top to bottom: watch the heartbeat, cause drift, isolate the pod in
        # Defender XDR, watch the heartbeat fail. Drift = a built-in binary copied to a new
        # path and executed: a file that was not in the image runs, which is the detection.
        ("binary drift + isolation (x-mdc-allowed)", [
            ("1. heartbeat log, last 2 min", "kubectl logs -n x-mdc-allowed deploy/webapp --since=2m"),
            ("1b. live TCP connections of the pod (netstat -antp style)", CONNS_CMD),
            ("2. TRIGGER binary drift (copy /bin/ls to a new path, run it)",
             'kubectl exec -n x-mdc-allowed deploy/webapp -- sh -c '
             '"mkdir -p /opt/mdc-drift && cp /bin/ls /opt/mdc-drift/drift-ls '
             '&& /opt/mdc-drift/drift-ls -la /opt/mdc-drift"'),
            (f"2b. TRIGGER crypto mining alert (contact {MINING_POOL})", MINING_DRILL_CMD),
            ("3. isolation evidence: network policies", "kubectl get networkpolicies -n x-mdc-allowed -o wide"),
            # Pods a Defender response action has restricted, in any namespace. "Isolate pod" labels
            # mdc-deny-all-network=true, "restrict pod access" mdc-block-sensitive-interfaces=true.
            # A label selector cannot OR two labels, so both become columns (custom-columns prints
            # <none> for a missing one), grep keeps the header plus every row where either says
            # true, and column -t re-aligns what is left.
            ("3b. pods restricted by Defender response actions (isolated or restricted access)",
             'kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,POD:.metadata.name,STATUS:.status.phase,ISOLATED:.metadata.labels.mdc-deny-all-network,RESTRICTED:.metadata.labels.mdc-block-sensitive-interfaces | grep -wE "NAMESPACE|true" | column -t'),
            ("   network policies in full", "kubectl get networkpolicies -n x-mdc-allowed -o yaml"),
            ("   cilium policies", "kubectl get ciliumnetworkpolicies -n x-mdc-allowed -o wide"),
            ("4. heartbeat log, last 30 s (ERROR = isolated)", "kubectl logs -n x-mdc-allowed deploy/webapp --since=30s"),
            ("pods with labels", "kubectl get pods -n x-mdc-allowed -o wide --show-labels"),
            ("heartbeat target", "kubectl get configmap panel-heartbeat -n x-mdc-allowed -o yaml"),
        ]),
        ("accepted risk", [
            ("workloads claiming accepted risk",
             "kubectl get pods -A -l risk.acceptance/state=accepted "
             "-o custom-columns=NS:.metadata.namespace,POD:.metadata.name,"
             "EXPIRES:.metadata.labels['risk\\.acceptance/expires'],"
             "CVES:.metadata.annotations['risk\\.acceptance/cves']"),
            ("who approved, and until when",
             "kubectl get pods -A -l risk.acceptance/state=accepted "
             "-o custom-columns=POD:.metadata.name,"
             "BY:.metadata.annotations['risk\\.acceptance/approved-by'],"
             "EXPIRES:.metadata.labels['risk\\.acceptance/expires'],"
             "EXEMPTION:.metadata.annotations['risk\\.acceptance/defender-exemption']"),
            ("expiring soonest first",
             "kubectl get pods -A -l risk.acceptance/state=accepted "
             "--sort-by=.metadata.labels['risk\\.acceptance/expires'] "
             "-o custom-columns=EXPIRES:.metadata.labels['risk\\.acceptance/expires'],"
             "NS:.metadata.namespace,POD:.metadata.name"),
            ("the full attestation on one workload",
             "kubectl get deploy webapp -n x-mdc-allowed "
             "-o jsonpath={.spec.template.metadata.annotations}"),
            ("deployments carrying an acceptance",
             "kubectl get deploy -A -o custom-columns=NS:.metadata.namespace,"
             "NAME:.metadata.name,"
             "ACCEPTED:.spec.template.metadata.labels['risk\\.acceptance/state'],"
             "TICKET:.spec.template.metadata.annotations['risk\\.acceptance/ticket']"),
            ("workloads WITHOUT an acceptance claim",
             "kubectl get pods -A -l '!risk.acceptance/state' "
             "-o custom-columns=NS:.metadata.namespace,POD:.metadata.name"),
        ]),
        ("demo workloads", [
            ("blocked namespace", "kubectl get deploy,rs,pods -o wide -n x-mdc-blocked"),
            ("allowed public app", "kubectl get deploy,pods,svc -o wide -n x-mdc-allowed"),
            ("ops / runner tier", "kubectl get pods -o wide -n demo-ops"),
            ("alert-simulation job", "kubectl get jobs,pods -n demo-ops"),
            ("alert-simulation logs", "kubectl logs -n demo-ops job/mdc-alert-triage --tail=200"),
            ("images actually running", "kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,IMAGE:.spec.containers[*].image"),
            ("pods running as root", "kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,RUNASNONROOT:.spec.securityContext.runAsNonRoot"),
            ("privileged containers", "kubectl get pods -A -o custom-columns=NS:.metadata.namespace,POD:.metadata.name,PRIV:.spec.containers[*].securityContext.privileged"),
        ]),
    ]



def _api_key_ok():
    """True when the caller presented the configured API key. Constant-time compare, and
    never true when no key is configured - an unset key must lock the door, not open it."""
    if not API_KEY:
        return False
    presented = request.headers.get(API_KEY_HEADER, "")
    return bool(presented) and hmac.compare_digest(presented, API_KEY)


@app.before_request
def _require_basic_auth():
    """Two ways in, both enforced here:
      - browser: HTTP Basic (basic mode). In entra mode EasyAuth has already rejected
        anonymous requests before they ever reach this process.
      - machine: the API key header, accepted on /api/* only, so a leaked key can never
        drive the HTML console.
    """
    if request.path in OPEN_PATHS:
        return None
    if request.path.startswith(API_PREFIX) and _api_key_ok():
        return None
    if not BASIC_ON:
        return None
    a = request.authorization
    ok = (a is not None and a.type == "basic"
          and hmac.compare_digest(a.username or "", BASIC_USER)
          and hmac.compare_digest(a.password or "", BASIC_PASSWORD))
    if ok:
        return None
    if request.path.startswith(API_PREFIX):
        return jsonify(error="authentication required",
                       hint=f"send the API key in the {API_KEY_HEADER} header, "
                            "or use HTTP Basic"), 401
    return Response("authentication required\n", 401,
                    {"WWW-Authenticate": 'Basic realm="AKS control panel"'})


def _end_user():
    """Who is driving the panel, for Defender for AI end-user attribution.
    entra mode -> the EasyAuth principal header; basic mode -> the Basic username."""
    h = request.headers
    who = h.get("X-MS-CLIENT-PRINCIPAL-NAME") or h.get("X-Ms-Client-Principal-Name")
    if not who and _api_key_ok():
        who = "apikey"
    if not who and BASIC_ON:
        a = request.authorization
        who = f"basic:{a.username}" if a and a.username else None
    return (who or "anonymous"), (h.get("X-Forwarded-For", "").split(",")[0].strip() or None)


# ---- kubernetes client ----------------------------------------------------
def cluster_ca_file():
    """Write the cluster CA to disk and return its path, or None when it cannot be found.

    Without it every call dies as SSLCertVerificationError "unable to get local issuer
    certificate", because the API server certificate is signed by the cluster CA and that
    CA is in no public trust store."""
    global _ca_file_cached
    if _ca_file_cached:
        return _ca_file_cached
    b64 = AKS_CA_CERT_B64
    if not b64 and AKS_RESOURCE_ID:
        import requests
        import yaml
        from azure.identity import DefaultAzureCredential
        token = DefaultAzureCredential().get_token(f"{ARM_ENDPOINT}/.default").token
        r = requests.post(
            f"{ARM_ENDPOINT}{AKS_RESOURCE_ID}/listClusterUserCredential"
            f"?api-version={AKS_ARM_API_VERSION}",
            headers={"Authorization": f"Bearer {token}"}, json={}, timeout=30)
        r.raise_for_status()
        kubeconfig = yaml.safe_load(base64.b64decode(r.json()["kubeconfigs"][0]["value"]))
        b64 = kubeconfig["clusters"][0]["cluster"]["certificate-authority-data"]
    if not b64:
        return None
    with open(CA_CERT_PATH, "wb") as fh:
        fh.write(base64.b64decode(b64))
    _ca_file_cached = CA_CERT_PATH
    return _ca_file_cached


def k8s_api_client():
    """ApiClient for the AKS API server, authenticated with the app's managed identity."""
    from azure.identity import DefaultAzureCredential
    from kubernetes import client as kclient
    token = DefaultAzureCredential().get_token(f"{AKS_AAD_SERVER}/.default").token
    cfg = kclient.Configuration()
    cfg.host = f"https://{AKS_FQDN}:443"
    cfg.api_key = {"authorization": f"Bearer {token}"}
    cfg.verify_ssl = os.environ.get("K8S_VERIFY_SSL", "true").lower() != "false"
    if cfg.verify_ssl:
        ca = cluster_ca_file()
        if ca:
            cfg.ssl_ca_cert = ca
    return kclient.ApiClient(cfg), kclient


def k8s():
    """CoreV1Api against the AKS API server, authenticated with the app's managed identity."""
    c, kclient = k8s_api_client()
    return kclient.CoreV1Api(c), kclient.BatchV1Api(c), kclient


def runner_pod(api):
    pods = api.list_namespaced_pod(RUNNER_NS, label_selector=RUNNER_SELECTOR,
                                   field_selector="status.phase=Running")
    if not pods.items:
        raise RuntimeError(f"no running kubectl-runner in {RUNNER_NS}; "
                           f"apply app/k8s/base/30-kubectl-runner.yaml")
    return pods.items[0].metadata.name


# Shell aliases do not exist here: there is no shell, the argv is exec'd in the runner pod.
# So the alias is resolved in the panel, before the allowlist runs - otherwise 'k get pods'
# would be judged as the unknown binary 'k' instead of as kubectl.
ALIASES = {"k": "kubectl"}


def expand_alias(argv):
    """Return argv with a leading alias replaced by the real binary."""
    if argv and argv[0] in ALIASES:
        return [ALIASES[argv[0]]] + argv[1:]
    return argv


def allowed(argv):
    """Return (ok, reason) for a command, per KUBECTL_MODE."""
    if KUBECTL_MODE == "unrestricted":
        return True, ""
    if not argv:
        return False, "empty command"
    if argv[0] == "kubectl":
        verb = argv[1] if len(argv) > 1 else ""
        if verb in READONLY_VERBS:
            return True, ""
        if KUBECTL_MODE == "demo":
            return True, ""
        return False, (f"'{verb}' is not a read-only verb. KUBECTL_MODE={KUBECTL_MODE}; "
                       f"allowed: {sorted(READONLY_VERBS)}")
    if KUBECTL_MODE == "demo":
        return True, ""
    return False, f"only kubectl is allowed in KUBECTL_MODE={KUBECTL_MODE}"


# ---- UI -------------------------------------------------------------------
PAGE = """<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>AKS control panel</title>
<style>
 :root{
   color-scheme:dark;
   --bg:#0a0f1c; --bg2:#111a2e; --card:#141e35; --card2:#121b30; --line:#24334f; --line2:#31456b;
   --fg:#eaf1fb; --dim:#93a5c4; --accent:#4da3ff; --ok:#57d9a3; --warn:#f2c14e;
   --bad:#ff6b81; --violet:#a78bfa;
   --r:12px; --shadow:0 1px 0 rgba(255,255,255,.04), 0 8px 24px rgba(0,0,0,.35);
   --head:#0b1120; --surface:#0e1729; --surface2:#18233a; --th:#16213a; --row-line:#1b2740;
   --row-hover:#16233d; --btn:#1a2942; --btn-hover:#22355a; --scroll:#243453;
   --glow1:#16233f; --glow2:#10263f;
   /* text tints on tinted pills */
   --t-bad:#ff9aa9; --t-bad-soft:#ffc2cc; --t-warn:#f3cf7a; --t-ok:#7fe3bb; --t-info:#8cc6ff;
   --t-sys:#8fa3c4;
 }
 /* Light theme. The terminal panes follow it too: .term carries its own colour tokens for
    each theme (see "console"), so highlighted output stays readable on either background. */
 :root[data-theme=light]{
   color-scheme:light;
   --bg:#eef2f8; --bg2:#ffffff; --card:#ffffff; --card2:#f8fafd; --line:#dbe2ee; --line2:#c5cfdf;
   --fg:#0f1b2d; --dim:#566883; --accent:#1d6fd6; --ok:#0b7a52; --warn:#9a6700;
   --bad:#c8243f; --violet:#6a46d1;
   --shadow:0 1px 2px rgba(15,27,45,.06), 0 6px 18px rgba(15,27,45,.08);
   --head:#ffffff; --surface:#f3f6fb; --surface2:#e9eef6; --th:#f0f4fa; --row-line:#e7ecf4;
   --row-hover:#f2f6fd; --btn:#eef2f9; --btn-hover:#e1e9f6; --scroll:#c3cddd;
   --glow1:#dde8fb; --glow2:#e3effa;
   --t-bad:#b4203a; --t-bad-soft:#9e1c33; --t-warn:#8a5d00; --t-ok:#0d7a54; --t-info:#1a5fb4;
   --t-sys:#4f6280;
 }
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);
   color:var(--fg);font:15px/1.5 'Segoe UI',system-ui,-apple-system,sans-serif}
 /* The two big radials used to sit on <body>, so every scroll frame repainted a
    full-viewport gradient. On a fixed layer they are painted once and composited. */
 body::before{content:'';position:fixed;inset:0;z-index:-1;pointer-events:none;background:
    radial-gradient(1200px 600px at 15% -10%, var(--glow1) 0%, transparent 60%),
    radial-gradient(900px 500px at 100% 0%, var(--glow2) 0%, transparent 55%)}
 a{color:var(--accent)}
 /* ---- top bar ---- */
 header{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:14px;
   padding:12px 22px;background:var(--head);
   border-bottom:1px solid var(--line)}
 .brand{font-size:17px;font-weight:700;letter-spacing:.2px}
 .brand .sh{color:var(--accent)}
 .chip{font-size:11.5px;padding:3px 10px;border-radius:999px;border:1px solid var(--line2);
   background:var(--surface);color:var(--dim);white-space:nowrap}
 .chip b{color:var(--fg);font-weight:600}
 .live{display:inline-flex;align-items:center;gap:6px}
 .dot{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite}
 @keyframes pulse{50%{opacity:.35}}
 @media (prefers-reduced-motion:reduce){.dot,.spin{animation:none}}
 .spacer{flex:1}
 /* ---- layout ---- */
 main{padding:20px 22px 40px;max-width:1700px;margin:0 auto}
 .grid{display:grid;gap:16px}
 .kpis{grid-template-columns:repeat(auto-fit,minmax(168px,1fr));margin-bottom:16px}
 .cols{grid-template-columns:repeat(auto-fit,minmax(520px,1fr))}
 .card{contain:layout paint style;
   background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--line);
   border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden}
 .card>h2{margin:0;padding:12px 16px;font-size:12px;letter-spacing:1.3px;text-transform:uppercase;
   color:var(--accent);border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px}
 .card>h2 .muted{margin-left:auto;font-size:11px;letter-spacing:.3px;text-transform:none;color:var(--dim);font-weight:400}
 .body{padding:14px 16px}
 .full{grid-column:1/-1}
 /* ---- kpi tile ---- */
 .kpi{padding:14px 16px}
 .kpi .n{font-size:30px;font-weight:700;line-height:1.05;letter-spacing:-.5px}
 .kpi .l{font-size:11.5px;color:var(--dim);text-transform:uppercase;letter-spacing:1.1px;margin-top:4px}
 .kpi.good .n{color:var(--ok)} .kpi.warn .n{color:var(--warn)} .kpi.bad .n{color:var(--bad)}
 /* ---- tables ---- */
 table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
 th{position:sticky;top:0;background:var(--th);text-align:left;padding:8px 10px;color:var(--dim);
   font-weight:600;font-size:11.5px;letter-spacing:.7px;text-transform:uppercase;border-bottom:1px solid var(--line)}
 td{padding:7px 10px;border-bottom:1px solid var(--row-line)}
 tbody tr:hover{background:var(--row-hover)}
 /* No overscroll-behavior:contain here: at the end of a box the wheel must hand over to the
    page, or every table becomes a trap and the only way down is the page scrollbar. */
 .scroll{max-height:340px;overflow:auto;contain:content}
 /* Skip rendering work for blades that are off screen; the reserved size keeps the
    scrollbar honest so nothing jumps when they come into view. */
 .card.full{content-visibility:auto;contain-intrinsic-size:auto 420px}
 .card.expanded{content-visibility:visible}
 /* ---- expand a blade to the whole page ---- */
 .exp{background:var(--surface);border:1px solid var(--line2);color:var(--dim);border-radius:7px;
   padding:2px 8px;font-size:12px;line-height:1.4;cursor:pointer}
 .exp:hover{color:var(--fg);border-color:var(--accent)}
 /* ---- collapse a blade to its title bar ---- */
 .card.collapsed>*:not(h2){display:none}
 .card.collapsed>h2{border-bottom:0}
 .card.collapsed{opacity:.8;cursor:pointer}
 .card>h2{cursor:pointer;user-select:none}
 .card.collapsed:hover{opacity:1}
 .backdrop{position:fixed;inset:0;background:rgba(3,7,15,.62);z-index:50}
 .card.expanded{position:fixed;inset:14px;z-index:60;margin:0;display:flex;flex-direction:column;
   overflow:auto;box-shadow:0 24px 64px rgba(0,0,0,.6)}
 .card.expanded>h2{position:sticky;top:0;z-index:2;background:var(--card)}
 .card.expanded .rowbtn{position:relative;z-index:1}
 /* the inner panes cap their own height for the dashboard layout; let them fill instead */
 .card.expanded .scroll{max-height:none}
 .card.expanded .term{flex:1;display:flex;flex-direction:column}
 .card.expanded .term pre{max-height:none;flex:1}
 body.locked{overflow:hidden}
 /* ---- right-click menu on a workload row ---- */
 .menu{position:fixed;z-index:70;min-width:260px;max-width:min(460px,92vw);padding:5px;
   background:var(--card);border:1px solid var(--line2);border-radius:10px;
   box-shadow:0 14px 40px rgba(0,0,0,.55);font-size:12.5px}
 .menu .mh{padding:6px 9px;color:var(--dim);font-size:11px;border-bottom:1px solid var(--line);
   margin-bottom:4px;word-break:break-all}
 .menu button{display:flex;gap:8px;align-items:center;width:100%;text-align:left;
   background:none;border:0;color:var(--fg);padding:6px 9px;border-radius:7px;cursor:pointer}
 .menu button:hover{background:var(--surface2)}
 .menu .sep{height:1px;background:var(--line);margin:4px 0}
 .menu .cn{color:var(--accent);font-family:ui-monospace,Consolas,monospace}
 .menu .ci{margin-left:auto;color:var(--dim);font-size:11px}
 .rowbtn{background:var(--surface);border:1px solid var(--line2);color:var(--dim);border-radius:6px;
   padding:1px 7px;font-size:11.5px;cursor:pointer}
 .rowbtn:hover{color:var(--fg);border-color:var(--accent)}
 .mono{font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:12.5px}
 /* ---- pills ---- */
 .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:600;
   border:1px solid transparent;white-space:nowrap}
 .p-ok{background:rgba(87,217,163,.14);color:var(--ok);border-color:rgba(87,217,163,.35)}
 .p-warn{background:rgba(242,193,78,.14);color:var(--warn);border-color:rgba(242,193,78,.35)}
 .p-bad{background:rgba(255,107,129,.14);color:var(--bad);border-color:rgba(255,107,129,.38)}
 .p-dim{background:var(--surface2);color:var(--dim);border-color:var(--line2)}
 /* ---- alert entity chips ---- */
 .ent{display:inline-flex;align-items:baseline;gap:6px;margin:2px 5px 2px 0;padding:2px 9px;
   border-radius:8px;border:1px solid var(--line2);background:var(--surface);font-size:11.5px;
   max-width:100%;word-break:break-all}
 .ent b{font-weight:700;font-size:10.5px;letter-spacing:.4px;text-transform:uppercase;
   white-space:nowrap;color:var(--dim)}
 .ent span{font-family:ui-monospace,Consolas,monospace;color:var(--fg)}
 .ent.e-process b,.ent.e-file b{color:var(--warn)}
 .ent.e-dns b,.ent.e-ip b{color:var(--bad)}
 .ent.e-container b,.ent.e-K8s-pod b,.ent.e-K8s-namespace b,.ent.e-container-image b{color:var(--accent)}
 .ent.e-K8s-cluster b,.ent.e-host b{color:var(--violet)}
 /* ---- namespace reset ---- */
 button.danger{background:rgba(255,107,129,.10);border-color:rgba(255,107,129,.45);color:var(--t-bad)}
 button.danger:hover{background:rgba(255,107,129,.2);border-color:var(--bad)}
 .p-info{background:rgba(77,163,255,.13);color:var(--t-info);border-color:rgba(77,163,255,.35)}
 .p-edge{background:rgba(255,107,129,.13);color:var(--t-bad);border-color:rgba(255,107,129,.32)}
 .p-internal{background:rgba(242,193,78,.13);color:var(--t-warn);border-color:rgba(242,193,78,.32)}
 .p-sandbox{background:rgba(87,217,163,.13);color:var(--t-ok);border-color:rgba(87,217,163,.3)}
 .p-system{background:var(--surface2);color:var(--t-sys);border-color:var(--line2)}
 /* ---- Defender alert severity ---- */
 .sev{font-weight:700;letter-spacing:.4px;text-transform:uppercase;font-size:10.5px}
 .sev-high{background:rgba(255,107,129,.18);color:var(--t-bad);border-color:rgba(255,107,129,.5)}
 .sev-medium{background:rgba(242,193,78,.16);color:var(--warn);border-color:rgba(242,193,78,.45)}
 .sev-low{background:rgba(87,217,163,.14);color:var(--t-ok);border-color:rgba(87,217,163,.35)}
 .sev-informational{background:rgba(77,163,255,.13);color:var(--t-info);border-color:rgba(77,163,255,.35)}
 .sev-unknown{background:var(--surface2);color:var(--t-sys);border-color:var(--line2)}
 /* ---- controls ---- */
 input,select,button{font:inherit;color:var(--fg);background:var(--surface);border:1px solid var(--line2);
   border-radius:9px;padding:8px 11px;transition:.15s}
 input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(77,163,255,.16)}
 button{cursor:pointer;background:var(--btn);border-color:var(--line2);font-weight:600}
 button:hover{background:var(--btn-hover);border-color:var(--accent)}
 button.primary{background:linear-gradient(180deg,#2f7fd6,#2568b4);border-color:#3b8ee0;color:#fff}
 button.primary:hover{filter:brightness(1.12)}
 button.ghost{background:transparent}
 button:disabled{opacity:.5;cursor:not-allowed}
 .row{display:flex;gap:9px;flex-wrap:wrap;align-items:center}
 /* ---- console ---- */
 /* The console has its own tokens per theme. Everything inside it (status words, check
    reports, yaml/json) uses these, never the page tokens, so no colour is tuned for one
    background only. Syntax palette: teal keys, peach values, lavender numbers/booleans. */
 .term{--bad:#ff6b81;--ok:#57d9a3;--warn:#f2c14e;--accent:#4da3ff;--dim:#93a5c4;--line:#24334f;
   --fg:#eaf1fb;--t-fg:#cfe0f6;--t-bg:#070c17;--t-bar:#0c1424;--t-dot:#2b3a58;
   --hl-bad:#ff8d9e;--hl-dim:#6f83a6;
   --fx-key:#6fd6c6;--fx-str:#f0b98d;--fx-lit:#c4a1ff;--fx-punct:#6f83a6;
   color-scheme:dark;background:var(--t-bg);border:1px solid var(--line);border-radius:10px;margin-top:12px;overflow:hidden}
 :root[data-theme=light] .term{--bad:#c8243f;--ok:#0b7a52;--warn:#9a6700;--accent:#1d6fd6;--dim:#566883;--line:#dbe2ee;
   --fg:#0f1b2d;--t-fg:#1f2d42;--t-bg:#fbfcfe;--t-bar:#f1f5fa;--t-dot:#c5cfdf;
   --hl-bad:#c8243f;--hl-dim:#7a8aa3;
   --fx-key:#0a7d72;--fx-str:#a24f17;--fx-lit:#7a3fd1;--fx-punct:#8b99ae;
   color-scheme:light}
 .term .bar{display:flex;align-items:center;gap:8px;padding:7px 12px;background:var(--t-bar);
   border-bottom:1px solid var(--line);font-size:11.5px;color:var(--dim)}
 .term .bar .d{width:9px;height:9px;border-radius:50%;background:var(--t-dot)}
 .term pre{margin:0;padding:13px 15px;max-height:400px;overflow:auto;
   contain:content;white-space:pre-wrap;
   word-break:break-word;font-family:ui-monospace,'Cascadia Code',Consolas,monospace;font-size:12.5px;color:var(--t-fg)}
 .spin{width:12px;height:12px;border:2px solid #2b3a58;border-top-color:var(--accent);
   border-radius:50%;animation:spin .7s linear infinite;display:inline-block}
 @keyframes spin{to{transform:rotate(360deg)}}
 /* ---- scenario picker ---- */
 .grp{margin:0 0 12px}
 .grp .gt{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--violet);margin-bottom:6px;font-weight:700}
 .scns{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:4px}
 .scn-l{display:flex;gap:7px;align-items:center;padding:5px 8px;border-radius:7px;cursor:pointer;
   font-size:12.5px;border:1px solid transparent}
 .scn-l:hover{background:var(--surface2);border-color:var(--line)}
 .scn-l input{padding:0;margin:0;accent-color:var(--accent)}
 .empty{color:var(--dim);font-size:13px;padding:10px 2px}
 /* ---- console highlighting ---- */
 .hl-bad{color:var(--hl-bad);font-weight:700}
 .hl-warn{color:var(--warn);font-weight:600}
 .hl-ok{color:var(--ok)}
 .hl-cmd{color:var(--accent);font-weight:600}
 .hl-dim{color:var(--hl-dim)}
 .hl-lbad{background:rgba(255,107,129,.10);box-shadow:inset 3px 0 0 var(--bad)}
 .hl-lwarn{background:rgba(242,193,78,.08);box-shadow:inset 3px 0 0 var(--warn)}
 /* which control spoke: Defender (red) or Azure Policy / Gatekeeper (violet) */
 .hl-lazp{background:rgba(167,139,250,.10);box-shadow:inset 3px 0 0 var(--violet)}
 .hl-azp{color:var(--violet);font-weight:700}
 .hl-src{display:inline-block;padding:0 6px;margin-right:6px;border-radius:4px;font-size:10.5px;
   font-weight:800;letter-spacing:.05em;vertical-align:1px}
 .hl-src.def{background:rgba(255,107,129,.2);color:var(--bad)}
 .hl-src.azp{background:rgba(167,139,250,.22);color:var(--violet)}
 /* check reports (verify admission): ✔ / ✘ / ! lines, hints, and the closing verdict */
 .hl-lok{background:rgba(87,217,163,.08);box-shadow:inset 3px 0 0 var(--ok)}
 .hl-pass{color:var(--ok);font-weight:600}
 .hl-mark{display:inline-block;min-width:1.4em;text-align:center;border-radius:4px;margin-right:2px}
 .hl-mark.ok{background:rgba(87,217,163,.18);color:var(--ok)}
 .hl-mark.bad{background:rgba(255,107,129,.18);color:var(--bad)}
 .hl-mark.warn{background:rgba(242,193,78,.18);color:var(--warn)}
 .hl-hint{color:var(--accent)}
 /* kubectl logs: the level token */
 .lv-bad{color:var(--hl-bad);font-weight:700} .lv-warn{color:var(--warn);font-weight:700}
 .lv-info{color:var(--accent);font-weight:700} .lv-dbg{color:var(--hl-dim);font-weight:600}
 .hl-title{color:var(--fg);font-weight:700}
 .hl-verdict{display:inline-block;padding:1px 10px;border-radius:999px;font-weight:800;letter-spacing:.04em}
 .hl-verdict.ok{background:rgba(87,217,163,.16);color:var(--ok);box-shadow:0 0 0 1px rgba(87,217,163,.45)}
 .hl-verdict.bad{background:rgba(255,107,129,.16);color:var(--bad);box-shadow:0 0 0 1px rgba(255,107,129,.45)}
 .fx-key{color:var(--fx-key)}
 .fx-str{color:var(--fx-str)}
 .fx-lit{color:var(--fx-lit)}
 .fx-punct{color:var(--fx-punct)}
 .fx-comment{color:var(--fx-punct);font-style:italic}
 .fx-head{color:var(--dim);font-weight:700;letter-spacing:.02em}
 .term .bar .fmtcopy{font:inherit;font-size:10.5px;letter-spacing:.04em;cursor:pointer;
   color:var(--dim);background:transparent;border:1px solid var(--line);border-radius:999px;padding:0 8px}
 .term .bar .fmt[hidden] + .fmtcopy{margin-left:auto}
 .term .bar .fmtcopy:hover{color:var(--fx-key);border-color:var(--fx-key)}
 .term .bar .fmt{margin-left:auto;font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;
   color:var(--fx-key);border:1px solid var(--line);border-radius:999px;padding:0 8px}
 .hl-verdict.warn{background:rgba(242,193,78,.14);color:var(--warn);box-shadow:0 0 0 1px rgba(242,193,78,.45)}
 /* ---- gitops blade ---- */
 .subh{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--violet);
   font-weight:700;margin:14px 0 6px}
 .subh:first-child{margin-top:0}
 .gate{border:1px solid rgba(255,107,129,.45);background:rgba(255,107,129,.07);
   border-radius:10px;padding:10px 13px;margin-bottom:10px}
 .gate.other{border-color:rgba(242,193,78,.45);background:rgba(242,193,78,.06)}
 .gate.past{border-color:var(--line2);background:var(--surface);opacity:.8}
 .gate .gh{display:flex;flex-wrap:wrap;align-items:center;gap:8px;font-weight:600}
 .gate .gm{margin-top:6px;font-family:ui-monospace,Consolas,monospace;font-size:12px;
   color:var(--t-bad-soft);white-space:pre-wrap;word-break:break-word;max-height:7.5em;overflow:auto}
 .gate.azp{border-color:rgba(167,139,250,.5);background:rgba(167,139,250,.07)}
 .gate.other .gm{color:var(--t-warn)} .gate.azp .gm{color:var(--violet)} .gate.past .gm{color:var(--dim)}
 .gate .gf{margin-top:6px;font-size:11.5px;color:var(--dim);display:flex;flex-wrap:wrap;gap:12px}
 .msg{max-width:560px;font-size:12.5px;color:var(--dim);word-break:break-word}
 .rev{font-family:ui-monospace,Consolas,monospace;font-size:12px}
 .ok-banner{border:1px solid rgba(87,217,163,.35);background:rgba(87,217,163,.06);
   border-radius:10px;padding:9px 13px;margin-bottom:10px;color:var(--ok);font-size:13px}
 ::-webkit-scrollbar{width:10px;height:10px}
 ::-webkit-scrollbar-thumb{background:var(--scroll);border-radius:8px}
 ::-webkit-scrollbar-track{background:transparent}
</style>
<script>
// Theme before first paint, so a light-mode reader never sees a dark flash. An explicit
// choice is remembered per browser; without one the system setting decides.
function applyTheme(t){
  document.documentElement.dataset.theme=t;
  const b=document.getElementById('themebtn');
  if(b){b.textContent=t==='light'?'☾ dark':'☀ light';b.title=`switch to ${t==='light'?'dark':'light'} mode`}
}
function toggleTheme(){
  const t=document.documentElement.dataset.theme==='light'?'dark':'light';
  try{localStorage.setItem('panel-theme',t)}catch(e){}
  applyTheme(t);
}
(function(){
  let t=null;
  try{t=localStorage.getItem('panel-theme')}catch(e){}
  applyTheme(t||(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'));
  addEventListener('DOMContentLoaded',()=>applyTheme(document.documentElement.dataset.theme));
})();
</script>
<header>
  <span class=brand>🛡️ AKS <span class=sh>control panel</span></span>
  <span class="chip live"><span class=dot></span> <b id=clusterchip>{{aks or 'not configured'}}</b></span>
  <span class=chip>mode <b>{{mode}}</b></span>
  <span class=chip title="{{authhint}}">auth <b>{{authmode}}</b></span>
  {% if foundry %}<span class=chip>AI <b>{{model}}</b></span>{% endif %}
  <span class=spacer></span>
  <label class="chip live" style=cursor:pointer><input type=checkbox id=auto style="padding:0;margin:0;accent-color:var(--accent)"> auto-refresh 10s</label>
  <button class=ghost onclick=collapseAll(true) title="collapse every blade to its title bar">⊟ collapse all</button>
  <button class=ghost onclick=collapseAll(false) title="show every blade again">⊞ expand all</button>
  <button class=ghost onclick=refresh()>↻ refresh</button>
  <button class=ghost id=themebtn onclick=toggleTheme()>☀ light</button>
</header>
<main>
  <div class="grid kpis" id=kpis></div>
  <div class="grid cols">
    <section class=card><h2>Cluster <span class=muted id=cmeta></span></h2><div class=body id=overview><div class=empty>loading…</div></div></section>
    <section class=card><h2>Nodes</h2><div class="body scroll" id=nodes><div class=empty>loading…</div></div></section>

    <section class="card full"><h2>Workloads <span class=muted>namespace tiers decide the gate verdict</span></h2>
      <div class=body>
        <div class=row>
          <input id=q style="flex:1;min-width:280px"
                 placeholder="search any column: namespace, pod, image, node, status — * wildcards, -term excludes">
          <button class=ghost onclick="clearFilter()">clear</button>
          <button onclick=loadPods()>reload</button>
          <span class=muted id=podcount style="font-size:11.5px;color:var(--dim)"></span>
          <button class=danger onclick="resetNs('x-mdc-blocked')" title="kubectl delete namespace x-mdc-blocked - Flux recreates it on its next sync">🗑 delete x-mdc-blocked</button>
          <button class=danger onclick="resetNs('x-mdc-allowed')" title="kubectl delete namespace x-mdc-allowed - Flux recreates it on its next sync">🗑 delete x-mdc-allowed</button>
          <span class=spacer></span>
          <span class=muted style="font-size:11.5px;color:var(--dim)">right-click a row for containers</span>
          <span class="pill p-edge" title="x-mdc-blocked is selected by the admission rule; vulnerable Pods are denied.">x-mdc-blocked → deny</span>
          <span class="pill p-internal" title="x-mdc-allowed is outside the rule scope; the same vulnerable image runs behind a public LoadBalancer.">x-mdc-allowed → run</span>
          <span class="pill p-sandbox" title="namespace labelled tier=sandbox (demo-ops): dev, experiments and this panel's own kubectl runner. Everything is audited, nothing is blocked - so the lab can never gate off its own control plane.">sandbox → audit only</span>
          <span class="pill p-system" title="Kubernetes and platform namespaces (kube-system, kube-public, kube-node-lease, gatekeeper-system, mdc, flux-system). Not part of the demo tiers and never gated.">system → not gated</span>
        </div>
      </div>
      <div class=scroll id=pods><div class=empty>loading…</div></div>
    </section>

    <section class="card full"><h2>Admission controls · verify
      <span class=muted>sensor, image gate rules, misconfiguration policies, Azure Policy, three dry runs</span></h2>
      <div class=body>
        <div class=row>
          <button class=primary onclick=verifyAdmission() title="reads + three server-side dry runs in x-mdc-blocked (vulnerable app and privileged root pod must be denied, a restricted pod admitted); nothing is created">▶ verify gate + misconfiguration</button>
          <span class=spacer></span>
          <span class=muted style="font-size:11.5px;color:var(--dim)">output lands in the kubectl console · run it before the demo</span>
        </div>
        <div class=row style=margin-top:10px>
          <span class=muted style="font-size:11.5px;color:var(--dim)">deploy by hand · real pods named manual-*:</span>
          <button onclick="runInConsole(MANUAL.blocked)" title="vulnerable aks-webapp into x-mdc-blocked: the image gate should DENY it">🚫 vulnerable app → x-mdc-blocked</button>
          <button onclick="runInConsole(MANUAL.allowed)" title="the same vulnerable image into x-mdc-allowed: outside the rule scope, so it is ADMITTED">✅ vulnerable app → x-mdc-allowed</button>
          <button onclick="runInConsole(MANUAL.misconfig)" title="privileged root container (MCR base image) into x-mdc-blocked: the misconfiguration policy should DENY it">🧱 privileged root pod → x-mdc-blocked</button>
          <button onclick="runInConsole(MANUAL.restricted)" title="restricted non-root container (scanned CVE-free Alpine from ACR) into x-mdc-blocked: neither gate objects, so it is ADMITTED">✅ restricted pod → x-mdc-blocked</button>
          <button class=ghost onclick="runInConsole(MANUAL.status)" title="kubectl get pods -A -l origin=manual">status</button>
          <button class=ghost onclick="runInConsole(MANUAL.cleanup)" title="delete every manual-* pod (label origin=manual)">clean up</button>
        </div>
      </div>
    </section>

    <section class="card full"><h2>Isolation drill · x-mdc-allowed
      <span class=muted>binary drift → isolate the pod in Defender XDR → heartbeat fails</span></h2>
      <div class=body>
        <div class=row>
          <button onclick="runInConsole(DRILL.heartbeat)" title="kubectl logs -n x-mdc-allowed deploy/webapp --since=2m">① heartbeat log</button>
          <button onclick="runInConsole(DRILL.conns)" title="every TCP socket of the webapp pod with state and process, like netstat -antp (read via /proc, the image has no netstat)">🔌 connections</button>
          <button class=primary onclick="runInConsole(DRILL.drift)" title="copy /bin/ls to /opt/mdc-drift/drift-ls in the webapp pod and run it">② ⚠ trigger binary drift</button>
          <button class=primary onclick="runInConsole(DRILL.mining)" title="resolve and request {{ mining_pool }} from the webapp pod (use when drift does not fire)">②b ⛏ trigger crypto mining</button>
          <button onclick="runInConsole(DRILL.policies)" title="Defender's isolate action lands as a network policy">③ network policies</button>
          <button onclick="runInConsole(DRILL.restricted)" title="every pod a Defender response action restricted, any namespace: isolated (mdc-deny-all-network) or restricted access (mdc-block-sensitive-interfaces)">🔒 restricted pods</button>
          <button onclick="runInConsole(DRILL.recent)" title="kubectl logs -n x-mdc-allowed deploy/webapp --since=30s">④ heartbeat, last 30 s</button>
          <button id=aksbtn onclick="openAks()" disabled title="public LoadBalancer of x-mdc-allowed/Service webapp">↗ open aks-webapp</button>
          <span class=spacer></span>
          <span class=muted style="font-size:11.5px;color:var(--dim)">output lands in the kubectl console · isolate between ② and ③ in Defender XDR</span>
        </div>
      </div>
    </section>

    <section class="card full"><h2>Application connections · x-mdc-allowed
      <span class=muted>reported by the aks-webapp pod <span id=akspod></span>: heartbeat to ACA + workload-identity Blob access</span></h2>
      <div class=body id=connections><div class=empty>loading…</div></div>
    </section>

    <section class="card full"><h2>GitOps · Flux
      <span class=muted id=fluxmeta>Kustomizations, sources and admission denials</span></h2>
      <div class=body>
        <div class=row style=margin-bottom:10px>
          <button class=ghost id=fluxbtn onclick=refreshFlux()>↻ refresh</button>
          <label class=scn-l title="reload this blade every 5 seconds while the page is visible">
            <input type=checkbox id=fluxauto> auto-refresh 5s</label>
          <span class=muted id=fluxstamp style="font-size:11.5px;color:var(--dim)"></span>
        </div>
        <div id=flux><div class=empty>loading…</div></div>
      </div>
    </section>

    <section class="card full"><h2>Defender alerts
      <span class=muted id=alertmeta>Defender alerts API</span></h2>
      <div class=scroll id=alerts><div class=empty>loading…</div></div>
    </section>

    <section class="card full"><h2>kubectl console <span class=muted>mode {{mode}} · runs in the in-cluster runner via pods/exec</span></h2>
      <div class=body>
        <div class=row style=margin-bottom:8px>
          <select id=lib onchange="pickCmd()" style="flex:1;min-width:320px">
            <option value="">command library — pick one, it lands in the box below…</option>
            {% for group, cmds in library %}<optgroup label="{{ group }}">
              {% for label, cmd in cmds %}<option value="{{ cmd }}">{{ label }}</option>{% endfor %}
            </optgroup>{% endfor %}
          </select>
          <label class=scn-l title="run straight away instead of only filling the box">
            <input type=checkbox id=librun> run on pick</label>
        </div>
        <form class=row onsubmit="runCmd(event)">
          <input id=cmd style="flex:1;min-width:320px" placeholder="kubectl get pods -A   (k = kubectl · pipe into grep, head, tail, wc, sort, uniq, column)" value="kubectl get pods -A">
          <button class=primary id=cmdbtn>▶ run</button>
          <button type=button class=ghost onclick="copyOut('out')">copy</button>
          <button type=button class=ghost onclick="clearOut('out','cmdstate')">clear</button>
          <span class=muted style="font-size:11.5px;color:var(--dim)" title="filters after | run in the panel, not in a shell">k = kubectl · | grep head tail wc sort uniq column · enter</span>
        </form>
        <div class=term><div class=bar><span class=d></span><span id=cmdstate>ready</span><span id=cmdfmt class=fmt hidden></span><button type=button id=cmdcopy class=fmtcopy hidden onclick=copyDoc() title="copy the command output only: no $ command line, no [exit]/[done] marker">⧉ copy</button></div><pre id=out>Every command is executed through the AKS API server, so it is authenticated, authorized and audited.</pre></div>
      </div>
    </section>

    <section class="card full"><h2>Defender alert simulation <span class=muted id=simmeta></span></h2>
      <div class=body>
        <div id=simpick><div class=empty>loading scenarios…</div></div>
        <div class=row style=margin-top:10px>
          <button class=primary id=simbtn onclick=runSim()>▶ run</button>
          <button onclick=runSim()>⟳ re-run <span style=color:var(--dim)>(deletes the old Job)</span></button>
          <button class=ghost onclick=pickAll()>select all</button>
          <button class=ghost onclick=pickNone()>clear</button>
          <span class=spacer></span>
          <label class=scn-l title="hostPID + privileged + host mounts; needs KUBECTL_MODE=unrestricted">
            <input type=checkbox id=simpriv> privileged variant</label>
        </div>
        <div class=term><div class=bar><span class=d></span><span id=simstate>idle</span></div><pre id=simout>Pick scenarios and run. The panel creates a Kubernetes Job and streams its logs here.</pre></div>
      </div>
    </section>

    {% if foundry %}
    <section class="card full"><h2>AI chat <span class=muted>optional · {{model}} · Defender for AI watches this call</span></h2>
      <div class=body>
        <form class=row onsubmit="chat(event)">
          <select id=cmode><option value=model>model inference</option><option value=agent>published agent</option></select>
          <input id=prompt style="flex:1;min-width:300px" placeholder="ask something, or try a jailbreak prompt">
          <button class=primary>send</button>
        </form>
        <div class=term><div class=bar><span class=d></span><span id=chatstate>idle</span></div><pre id=chatout>A blocked jailbreak is the demo: Prompt Shields refuses it and Defender raises an alert.</pre></div>
      </div>
    </section>
    {% endif %}
  </div>
</main>
<script>
const $=i=>document.getElementById(i), j=async u=>(await fetch(u)).json(), esc=s=>String(s??'')
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const TIER={'x-mdc-blocked':'edge','x-mdc-allowed':'internal','demo-ops':'sandbox'};
const tierOf=n=>TIER[n]||(['kube-system','kube-public','kube-node-lease','flux-system','mdc','gatekeeper-system'].includes(n)?'system':'');
const tierPill=n=>{const t=tierOf(n);return t?`<span class="pill p-${t}">${t}</span>`:''};
function kpi(n,l,cls){return `<div class="card kpi ${cls||''}"><div class=n>${n}</div><div class=l>${l}</div></div>`}
function statusPill(s,r){
  if(s==='Running')return '<span class="pill p-ok">Running</span>';
  if(s==='Succeeded')return '<span class="pill p-dim">Succeeded</span>';
  if(s==='Pending')return '<span class="pill p-warn">Pending</span>';
  return `<span class="pill p-bad">${esc(s)}</span>`}
function tbl(rows,cols,render){
  if(!rows||!rows.length)return '<div class=empty>nothing here</div>';
  return `<table><thead><tr>${cols.map(c=>`<th>${c}</th>`).join('')}</tr></thead><tbody>`+
    rows.map(r=>`<tr>${cols.map(c=>`<td>${(render&&render(c,r))??esc(r[c])}</td>`).join('')}</tr>`).join('')+
    '</tbody></table>'}

async function loadOverview(){
  const o=await j('/api/overview');
  if(o.error){$('overview').innerHTML=`<div class=empty style=color:var(--bad)>${esc(o.error)}</div>`;
    $('kpis').innerHTML=kpi('—','cluster unreachable','bad');return null}
  $('cmeta').textContent=o.version;
  $('overview').innerHTML=`<table><tbody>
    <tr><td style=color:var(--dim)>cluster</td><td><b>${esc(o.cluster)}</b></td></tr>
    <tr><td style=color:var(--dim)>kubernetes</td><td>${esc(o.version)}</td></tr>
    <tr><td style=color:var(--dim)>namespaces</td><td>${o.namespaces.map(n=>tierPill(n)||`<span class="pill p-dim">${esc(n)}</span>`).join(' ')}</td></tr>
    </tbody></table>`;
  $('nodes').innerHTML=tbl(o.nodes,['name','status','version','os'],(c,r)=>
    c==='status'?(r.status==='Ready'?'<span class="pill p-ok">Ready</span>':'<span class="pill p-bad">NotReady</span>'):null);
  return o}
// The filter is a plain substring match per term, with * and ? as wildcards, terms ANDed,
// and a leading - excluding. It runs over the FULL row (every column joined), so one box
// covers namespace, pod, image, node and status without the reader choosing a field first.
let POD_ROWS=[];
function segAt(h,seg,pos){
  if(pos+seg.length>h.length)return false;
  for(let i=0;i<seg.length;i++){const c=seg[i];if(c!=='?'&&c!==h[pos+i])return false}
  return true;
}
function findSeg(h,seg,from){
  for(let p=from;p+seg.length<=h.length;p++)if(segAt(h,seg,p))return p;
  return -1;
}
// Plain text is a substring match; * and ? turn it into a wildcard walk. Deliberately
// unanchored, because in a search box 'atlas*latest' means "atlas, then later latest",
// not "the whole cell". Built without RegExp so no escaping is needed for ( ) . : / in
// image names - which is exactly what a naive regex build gets wrong.
function wildMatch(hay,term){
  const h=hay.toLowerCase(), t=term.toLowerCase();
  if(t.indexOf('*')<0&&t.indexOf('?')<0)return h.indexOf(t)>=0;
  let pos=0;
  for(const seg of t.split('*')){
    if(!seg)continue;
    const at=findSeg(h,seg,pos);
    if(at<0)return false;
    pos=at+seg.length;
  }
  return true;
}
function filterRows(rows,q){
  const terms=q.trim().split(/\s+/).filter(Boolean);
  if(!terms.length)return rows;
  return rows.filter(r=>{
    const hay=[r.namespace,r.name,r.status,r.image,r.node,String(r.restarts)].join(' ');
    return terms.every(t=>t.startsWith('-')&&t.length>1
      ? !wildMatch(hay,t.slice(1))
      : wildMatch(hay,t));
  });
}
function renderPods(){
  const q=$('q').value, rows=filterRows(POD_ROWS,q);
  $('podcount').textContent = q.trim()
    ? `${rows.length} of ${POD_ROWS.length} pods` : `${POD_ROWS.length} pods`;
  VISIBLE_PODS=rows;
  $('pods').innerHTML=tbl(rows,['namespace','name','status','restarts','image','node','logs'],(c,r)=>{
    if(c==='logs')return `<button class=rowbtn onclick="podLogs('${esc(r.namespace)}','${esc(r.name)}')"`
      +` title="kubectl logs --all-containers">logs</button>`;
    if(c==='namespace')return `${tierPill(r.namespace)} <span class=mono>${esc(r.namespace)}</span>`;
    if(c==='status')return statusPill(r.status);
    if(c==='restarts')return r.restarts>0?`<span class="pill p-warn">${r.restarts}</span>`:'<span style=color:var(--dim)>0</span>';
    if(c==='image')return `<span class=mono title="${esc(r.image)}">${esc(String(r.image).split('/').pop())}</span>`;
    if(c==='name'){
      const n=(r.containers||[]).length;
      return `<span class=mono>${esc(r.name)}</span>`
        +(n>1?` <span class="pill p-warn" title="right-click for the container list">${n} containers</span>`:'');
    }
    return null});
  // The row index is what the context menu looks the pod up by.
  $('pods').querySelectorAll('tbody tr').forEach((tr,i)=>{
    tr.dataset.i=i;
    tr.oncontextmenu=e=>{e.preventDefault();openRowMenu(e,VISIBLE_PODS[i])};
  });
}
function clearFilter(){$('q').value='';renderPods()}
// The isolation drill. Drift = a built-in binary copied to a new path and executed: a file
// that was not in the image runs. exec is granted in x-mdc-allowed only.
const MANUAL={{ manual|tojson }};
const DRILL={
  heartbeat:'kubectl logs -n x-mdc-allowed deploy/webapp --since=2m',
  drift:'kubectl exec -n x-mdc-allowed deploy/webapp -- sh -c "mkdir -p /opt/mdc-drift && cp /bin/ls /opt/mdc-drift/drift-ls && /opt/mdc-drift/drift-ls -la /opt/mdc-drift"',
  mining:{{ mining_cmd|tojson }},
  conns:{{ conns_cmd|tojson }},
  policies:'kubectl get networkpolicies -n x-mdc-allowed -o wide',
  // Pods restricted by a Defender response: isolated (mdc-deny-all-network) or restricted
  // access (mdc-block-sensitive-interfaces). Both labels as columns, grep keeps either true,
  // column -t re-aligns the rows that are left.
  restricted:'kubectl get pods -A -o custom-columns=NAMESPACE:.metadata.namespace,POD:.metadata.name,STATUS:.status.phase,ISOLATED:.metadata.labels.mdc-deny-all-network,RESTRICTED:.metadata.labels.mdc-block-sensitive-interfaces | grep -wE "NAMESPACE|true" | column -t',
  recent:'kubectl logs -n x-mdc-allowed deploy/webapp --since=30s',
};
// Delete a demo namespace through the console, so it is executed, audited and visible like any
// other command. The runner may delete exactly these two (kubectl-runner-ns-delete).
// --wait=false returns at once; the namespace sits in Terminating until it is empty.
function resetNs(ns){
  if(!confirm(`Delete namespace ${ns} and everything in it? Flux recreates it and redeploys its workloads on the next sync (about a minute).`))return;
  runInConsole(`kubectl delete namespace ${ns} --wait=false`);
}

// ---- right-click menu: every container of the pod, each with its own log action ----
let VISIBLE_PODS=[];
const MAX_CONSOLE_CHARS=400000;   // ~5k lines of kubectl output
function closeMenu(){
  const m=$('rowmenu');
  if(!m)return;
  m.remove();
  removeEventListener('scroll',closeMenu,{capture:true});
}
function verifyAdmission(){
  const target=$('cmd').closest('section.card');
  if(target&&target.classList.contains('collapsed'))setCollapsed(target,false);
  const open=document.querySelector('section.card.expanded');
  if(open&&open!==target){toggleExpand(open);if(target)toggleExpand(target)}
  else if(!open&&target)target.scrollIntoView({behavior:'smooth',block:'start'});
  streamTo('out','cmdstate','cmdbtn','/api/verify-admission',{});
}
function runInConsole(cmd){
  $('cmd').value=cmd;
  const target=$('cmd').closest('section.card');
  if(target&&target.classList.contains('collapsed'))setCollapsed(target,false);
  const open=document.querySelector('section.card.expanded');
  // Triggered from an expanded blade, the output would stream into a card sitting behind
  // the overlay - visibly nothing happens. Hand the expansion to the console instead.
  if(open&&open!==target){toggleExpand(open);if(target)toggleExpand(target)}
  else if(!open&&target)target.scrollIntoView({behavior:'smooth',block:'start'});
  runCmd();
}
function podLogs(ns,pod,container){
  const c=container?` -c ${container}`:' --all-containers';
  runInConsole(`kubectl logs -n ${ns} ${pod}${c} --tail=200`);
}
function openRowMenu(e,row){
  closeMenu();
  if(!row)return;
  const m=document.createElement('div');
  m.id='rowmenu'; m.className='menu';
  const cs=row.containers||[];
  // &#39;: a command with single quotes (sh -c '...') would end the onclick attribute early.
  const item=(label,cmd)=>`<button onclick='closeMenu();runInConsole(${JSON.stringify(cmd).replace(/'/g,'&#39;')})'>${label}</button>`;
  m.innerHTML=`<div class=mh>${esc(row.namespace)} / <b>${esc(row.name)}</b></div>`
    + item('logs · all containers',`kubectl logs -n ${row.namespace} ${row.name} --all-containers --tail=200`)
    + item('describe pod',`kubectl describe pod -n ${row.namespace} ${row.name}`)
    + item('pod as YAML',`kubectl get pod -n ${row.namespace} ${row.name} -o yaml`)
    // The isolation drill lives on the pod it targets: only x-mdc-allowed grants exec.
    + (row.namespace==='x-mdc-allowed'?'<div class=sep></div>'
        + item('⚠ trigger binary drift (copy /bin/ls to a new path, run it)',
            `kubectl exec -n ${row.namespace} ${row.name} -- sh -c "mkdir -p /opt/mdc-drift && cp /bin/ls /opt/mdc-drift/drift-ls && /opt/mdc-drift/drift-ls -la /opt/mdc-drift"`)
        + item('⛏ trigger crypto mining (contact {{ mining_pool }})',
            DRILL.mining.replace('deploy/webapp',row.name))
        + item('🔌 live TCP connections (netstat -antp style)',
            DRILL.conns.replace('deploy/webapp',row.name))
        + item('heartbeat log · last 2 min',`kubectl logs -n ${row.namespace} ${row.name} --since=2m`):'')
    + (cs.length?'<div class=sep></div>':'')
    + cs.map(c=>`<button onclick='closeMenu();runInConsole(${JSON.stringify(
        `kubectl logs -n ${row.namespace} ${row.name} -c ${c.name} --tail=200`)})'>`
        + `<span class=cn>${esc(c.name)}</span>`
        + `<span class=ci>${c.init?'init · ':''}${c.ready?'ready':'not ready'}`
        + `${c.restarts?` · ${c.restarts} restarts`:''}</span></button>`).join('')
    + (cs.length?'<div class=sep></div>'+cs.map(c=>
        `<button onclick='closeMenu();runInConsole(${JSON.stringify(
          `kubectl logs -n ${row.namespace} ${row.name} -c ${c.name} --tail=200 --previous`)})'>`
        + `previous logs · <span class=cn>${esc(c.name)}</span></button>`).join(''):'');
  document.body.appendChild(m);
  // Attached only while the menu exists, and passive so it never blocks scrolling.
  addEventListener('scroll',closeMenu,{capture:true,passive:true});
  // Keep the menu on screen when the click lands near an edge.
  const r=m.getBoundingClientRect();
  m.style.left=Math.min(e.clientX,innerWidth-r.width-8)+'px';
  m.style.top=Math.min(e.clientY,innerHeight-r.height-8)+'px';
}
addEventListener('click',e=>{if(!e.target.closest('.menu'))closeMenu()});
async function loadPods(){
  const p=await j('/api/pods');
  if(p.error){$('pods').innerHTML=`<div class=empty style=color:var(--bad)>${esc(p.error)}</div>`;return null}
  POD_ROWS=p.pods;
  renderPods();
  return p}
let AKS_URL='';
function setAks(url,err){
  AKS_URL=url||'';
  const b=$('aksbtn'); if(!b)return;
  b.disabled=!AKS_URL;
  b.title=AKS_URL?`open ${AKS_URL} in a new tab`:(err||'aks-webapp address unknown');
}
function openAks(){ if(AKS_URL) window.open(AKS_URL,'_blank','noopener') }
async function loadConnections(){
  const box=$('connections');
  let d;
  try{d=await j('/api/connections')}catch(e){d={error:String(e)}}
  if(d.url) setAks(d.url);
  else j('/api/aks-webapp').then(a=>setAks(a.url,a.error)).catch(e=>setAks('',String(e)));
  $('akspod').textContent=d.pod?`(${d.pod})`:'';
  if(d.error){box.innerHTML=`<div class=empty style=color:var(--bad)>${esc(d.error)}</div>`;return}
  const h=d.heartbeat||{}, b=d.blob||{};
  const state=x=>x.status==='ok'?'<span class="pill p-ok">connected</span>'
    :x.status==='error'?'<span class="pill p-bad">error</span>'
    :'<span class="pill p-dim">not configured</span>';
  const conn=`<table><thead><tr><th>Connection</th><th>Status</th><th>Target</th><th>Last check</th><th>Detail</th></tr></thead><tbody>`+
    `<tr><td>ACA heartbeat</td><td>${state(h)}</td><td class=mono>${esc(h.target||'—')}</td><td>${esc(h.last_checked||'—')}</td><td>${esc(h.error||h.detail||'—')}</td></tr>`+
    `<tr><td>Sensitive Blob</td><td>${state(b)}</td><td class=mono>${esc(b.target||'—')}</td><td>${esc(b.last_checked||'—')}</td><td>${esc(b.error||(b.bytes?`${b.bytes} bytes · sha256 ${String(b.sha256).slice(0,12)}…`:'—'))}</td></tr>`+
    `</tbody></table>`;
  const records=b.records||[];
  const data=records.length
    ? `<div class=subh>${esc(b.classification||'FAKE SENSITIVE DATA')} · ${records.length} records</div>`+
      tbl(records,['customerId','name','email','accountTier','balanceEur'])
    : `<div class=empty>${b.configured?'waiting for Blob data…':'Blob connection is configured only on the AKS web app.'}</div>`;
  box.innerHTML=conn+data;
  return d}
function pickCmd(){
  const v=$('lib').value;
  if(!v)return;
  $('cmd').value=v;
  $('lib').selectedIndex=0;          // so picking the same entry twice still works
  if($('librun').checked) runCmd(); else $('cmd').focus();
}
const SEV_RANK={high:0,medium:1,low:2,informational:3};
function sevPill(v){
  const k=String(v||'').toLowerCase();
  const known=k in SEV_RANK;
  return `<span class="pill sev sev-${known?k:'unknown'}">${esc(v||'unknown')}</span>`;
}
async function loadAlerts(){
  const meta=$('alertmeta'), box=$('alerts');
  let d;
  try{d=await j('/api/alerts')}catch(e){d={error:String(e)}}
  if(d.error){
    box.innerHTML=`<div class=empty style=color:var(--bad)>${esc(d.error)}</div>`;
    meta.textContent='query failed';
    return;
  }
  const rows=(d.alerts||[]).slice().sort((a,b)=>{
    const ra=SEV_RANK[String(a.severity||'').toLowerCase()] ?? 9;
    const rb=SEV_RANK[String(b.severity||'').toLowerCase()] ?? 9;
    return ra-rb || String(b.started||'').localeCompare(String(a.started||''));
  });
  const high=rows.filter(r=>String(r.severity||'').toLowerCase()==='high').length;
  meta.innerHTML=rows.length
    ? `${rows.length} open${high?` · <b style="color:var(--bad)">${high} high</b>`:''} · ${esc(d.cluster||'')}`
    : `none open · ${esc(d.cluster||'')}`;
  if(d.note){meta.textContent=d.note;}
  if(!rows.length){
    box.innerHTML='<div class=empty>no active Defender alerts for this cluster. '
      +'Run a simulation below and give it a few minutes.</div>';
    return;
  }
  box.innerHTML=tbl(rows,['severity','alert','entities','intent','started','status'],(c,r)=>{
    if(c==='severity')return sevPill(r.severity);
    if(c==='status')return `<span class="pill p-dim">${esc(r.status)}</span>`;
    if(c==='started')return `<span class=mono>${esc(String(r.started||'').replace('T',' ').slice(0,19))}</span>`;
    if(c==='alert')return `<span title="${esc(r.description||'')}">${esc(r.alert)}</span>`;
    if(c==='entities'){
      const ents=r.entities||[];
      if(!ents.length)return `<span class=mono>${esc(r.entity||'')}</span>`;
      return ents.map(e=>`<span class="ent e-${esc(e.type)}" title="${esc(e.type)}: ${esc(e.value)}">`
        +`<b>${esc(e.type.replace('K8s-',''))}</b><span>${esc(clip(e.value,160))}</span></span>`).join('');
    }
    return null});
}
// ---- GitOps blade: Flux state, and the admission denial that explains a failed rollout ----
// Row buttons run a console command. The commands sit in an array and the button refers to
// one by index, so no resource name ever has to survive being quoted into an attribute.
let FLUX_CMDS=[];
const cbtn=(label,cmd)=>{FLUX_CMDS.push(cmd);
  return `<button class=rowbtn title="${esc(cmd)}" onclick="runInConsole(FLUX_CMDS[${FLUX_CMDS.length-1}])">${label}</button>`};
const FLUX_RES={Kustomization:'kustomizations.kustomize.toolkit.fluxcd.io',
  GitRepository:'gitrepositories.source.toolkit.fluxcd.io',
  OCIRepository:'ocirepositories.source.toolkit.fluxcd.io',
  HelmRelease:'helmreleases.helm.toolkit.fluxcd.io'};
const APPLIERS=['Kustomization','HelmRelease'];
// 'main@sha1:4f2c9e1...' -> 'main@4f2c9e1'
function shortRev(r){
  const s=String(r||''), m=s.match(/^(.*)@sha(?:1|256):([0-9a-f]{7})/);
  return m?`${m[1]}@${m[2]}`:(s.length>28?s.slice(0,28)+'…':s)}
function ago(t){
  const d=Date.parse(t);
  if(!t||isNaN(d))return '';
  const s=Math.max(0,Math.round((Date.now()-d)/1000));
  return s<90?`${s}s ago`:s<5400?`${Math.round(s/60)}m ago`
    :s<172800?`${Math.round(s/3600)}h ago`:`${Math.round(s/86400)}d ago`}
const clip=(s,n)=>{s=String(s||'');return s.length>n?s.slice(0,n)+'…':s};
// Flux condition / event reasons by colour. Order matters: 'ProgressingWithRetry' is a
// retry (amber) before it is progress (blue), and anything Failed beats everything.
function reasonKind(r){
  const s=String(r||'');
  if(!s)return '';
  if(/Fail|Error|Stalled|Denied|Invalid|NotFound|Unauthorized/i.test(s))return 'bad';
  if(/Retry|Timeout|DependencyNotReady|Waiting|Unknown|Suspended|Deprecat/i.test(s))return 'warn';
  if(/Progress|Reconciling|InProgress|Pending|Started|Upgrading|Installing/i.test(s))return 'info';
  if(/Succeeded|Success|UpToDate|Ready|Stored|NewArtifact|Applied|Complete|Healthy/i.test(s))return 'ok';
  return 'dim'}
function reasonPill(r){
  const k=reasonKind(r);
  return k?`<span class="pill p-${k}">${esc(r)}</span>`:'<span style=color:var(--dim)>—</span>'}
function fluxPill(o){
  if(o.suspended)return '<span class="pill p-dim">suspended</span>';
  if(o.ready==='True')return '<span class="pill p-ok">Ready</span>';
  if(o.ready==='False'&&(o.denials||[]).length)
    return '<span class="pill p-bad" title="its pods were refused by the admission controller">⛔ blocked by gate</span>';
  if(o.ready==='False')return `<span class="pill p-bad">${esc(o.reason||'Failed')}</span>`;
  return `<span class="pill p-warn">${esc(o.reason||'Reconciling')}</span>`}
const GATE={defender:['⛔ Defender admission controller','gate'],
            'azure-policy':['🛂 Azure Policy (Gatekeeper)','gate azp'],
            policy:['⚠ admission policy (VAP)','gate other'],
            webhook:['⚠ admission webhook','gate other']};
function denialCard(d){
  const [label,cls]=GATE[d.gate]||GATE.webhook;
  return `<div class="${cls}${d.active?'':' past'}"><div class=gh>${label} blocked
      ${tierPill(d.namespace)} <span class=mono>${esc(d.namespace)} / ${esc(d.workload)}</span>
      ${d.active?'<span class="pill p-bad">active</span>':'<span class="pill p-dim">recent · not failing now</span>'}
      <span class=spacer></span>
      ${cbtn('events',`kubectl get events -n ${d.namespace} --field-selector reason=FailedCreate --sort-by=.lastTimestamp`)}
      ${cbtn('describe',`kubectl describe ${String(d.object).replace('/',' ')} -n ${d.namespace}`)}
    </div>
    <div class=gm>${esc(d.detail)}</div>
    <div class=gf>
      ${d.rule?`<span>rule <b class=mono>${esc(d.rule)}</b></span>`:''}
      <span>by <span class=mono>${esc(d.by)}</span></span>
      ${(d.images||[]).length?`<span>image <span class=mono>${esc(d.images.join(', '))}</span></span>`:''}
      ${d.flux?`<span>applied by <span class=mono>${esc(d.flux)}</span></span>`:''}
      <span>${esc(d.count)}× · last ${esc(ago(d.last))}</span>
    </div></div>`}
function fluxCell(c,r){
  if(c==='status')return fluxPill(r);
  if(c==='name')return `<span class=mono>${esc(r.name)}</span>`
    +((r.dependsOn||[]).length?`<div style="color:var(--dim);font-size:11.5px">after ${esc(r.dependsOn.join(', '))}</div>`:'');
  if(c==='path')return `<span class=mono>${esc(r.path||r.source)}</span>`;
  if(c==='url')return `<span class=mono title="${esc(r.url)}">${esc(clip(r.url,60))}</span>`;
  if(c==='revision')return `<span class=rev title="${esc(r.revision)}">${esc(shortRev(r.revision))}</span>`
    // attempted != applied is the GitOps tell: the new commit is in, it never landed
    +(r.attempted&&r.attempted!==r.revision
      ?`<div class=rev style=color:var(--warn) title="last attempted, not applied: ${esc(r.attempted)}">→ ${esc(shortRev(r.attempted))}</div>`:'');
  if(c==='since')return `<span title="${esc(r.since)}">${esc(ago(r.since))}</span>`;
  if(c==='reason')return reasonPill(r.reason);
  if(c==='message')return `<div class=msg title="${esc(r.message)}">${esc(clip(r.message,260))}</div>`;
  if(c==='actions')return cbtn('describe',`kubectl describe ${FLUX_RES[r.kind]||r.kind} -n ${r.namespace} ${r.name}`);
  return null}
async function loadFlux(){
  const box=$('flux'), meta=$('fluxmeta');
  let d;
  try{d=await j('/api/flux')}catch(e){d={error:String(e)}}
  if(d.error){
    box.innerHTML=`<div class=empty style=color:var(--bad)>${esc(d.error)}</div>`;
    meta.textContent='query failed';
    return null}
  FLUX_CMDS=[];
  const s=d.summary, objs=d.objects||[], denials=d.denials||[];
  const appliers=objs.filter(o=>APPLIERS.includes(o.kind)), sources=objs.filter(o=>!APPLIERS.includes(o.kind));
  meta.innerHTML=`${s.ready}/${s.appliers} ready`
    +(s.failing?` · <b style="color:var(--bad)">${s.failing} failing</b>`:'')
    +(s.defender?` · <b style="color:var(--bad)">${s.defender} blocked by Defender</b>`:'')
    +(s.azure_policy?` · <b style="color:var(--violet)">${s.azure_policy} blocked by Azure Policy</b>`:'')
    +(s.suspended?` · ${s.suspended} suspended`:'')+` · ns ${esc(d.namespace)}`;
  const active=denials.filter(x=>x.active), past=denials.filter(x=>!x.active);
  let h='';
  if((d.errors||[]).length)
    h+=`<div class=empty style=color:var(--warn)>${d.errors.map(esc).join('<br>')}</div>`;
  h+='<div class=subh>admission denials</div>';
  h+=active.length?active.map(denialCard).join('')
    :`<div class=ok-banner>✔ nothing is being refused at admission right now${past.length?' · recent denials below':''}</div>`;
  h+=past.slice(0,5).map(denialCard).join('');
  h+='<div class=subh>kustomizations · helm releases</div>';
  h+=appliers.length?tbl(appliers,['status','reason','name','path','revision','since','message','actions'],fluxCell)
    :`<div class=empty>no Flux Kustomizations found. Is the microsoft.flux extension installed (DEPLOY_FLUX=true)?</div>`;
  h+='<div class=subh>sources</div>';
  h+=tbl(sources,['status','reason','name','url','revision','since','message','actions'],fluxCell);
  h+='<div class=subh>recent flux events</div>';
  h+=`<div class=scroll id=fluxevents>${tbl(d.events||[],['last','type','reason','object','message'],(c,r)=>{
    if(c==='last')return `<span title="${esc(r.last)}">${esc(ago(r.last))}</span>`;
    if(c==='type')return r.type==='Warning'?'<span class="pill p-warn">Warning</span>':'<span class="pill p-dim">Normal</span>';
    if(c==='reason')return reasonPill(r.reason);
    if(c==='object')return `<span class=mono>${esc(r.object)}</span>`;
    if(c==='message')return `<div class=msg title="${esc(r.message)}">${esc(clip(r.message,260))}</div>`
      +(r.count>1?` <span class="pill p-dim">${esc(r.count)}×</span>`:'');
    return null})}</div>`;
  // Auto-refresh rebuilds the blade every 10s; keep the events list where the reader left it.
  const prev=$('fluxevents'), top=prev?prev.scrollTop:0;
  box.innerHTML=h;
  if(top&&$('fluxevents'))$('fluxevents').scrollTop=top;
  $('fluxstamp').textContent='updated '+new Date().toLocaleTimeString();
  return d}
// One request at a time: a slow API server must not stack up 5-second reloads.
let FLUX_BUSY=false, FLUX_TIMER=null;
async function refreshFlux(){
  if(FLUX_BUSY)return;
  FLUX_BUSY=true; const b=$('fluxbtn'); b.disabled=true;
  try{await loadFlux()}finally{FLUX_BUSY=false; b.disabled=false}
}
function setFluxAuto(on){
  clearInterval(FLUX_TIMER); FLUX_TIMER=null;
  if(on)FLUX_TIMER=setInterval(()=>{if(!document.hidden&&!$('rowmenu'))refreshFlux()},5000);
  try{localStorage.setItem('panel-flux-auto',on?'1':'')}catch(e){}
}
addEventListener('DOMContentLoaded',()=>{
  const c=$('fluxauto');
  let on=false;
  try{on=localStorage.getItem('panel-flux-auto')==='1'}catch(e){}
  c.checked=on; setFluxAuto(on);
  c.addEventListener('change',e=>setFluxAuto(e.target.checked));
});
async function refresh(){
  const [o,p,,f]=await Promise.all([loadOverview(),loadPods(),loadAlerts(),loadFlux(),loadConnections()]);
  if(!o||!p)return;
  const run=p.pods.filter(x=>x.status==='Running').length,
        bad=p.pods.filter(x=>!['Running','Succeeded'].includes(x.status)).length,
        rs=p.pods.reduce((a,x)=>a+(x.restarts||0),0);
  const fs=f&&f.summary;
  $('kpis').innerHTML=kpi(o.node_count,'nodes')+kpi(run,'pods running','good')+
    kpi(bad,'not running',bad?'bad':'')+kpi(rs,'restarts',rs?'warn':'')+
    kpi(o.namespaces.filter(n=>tierOf(n)&&tierOf(n)!=='system').length,'demo namespaces')+
    (fs?kpi(`${fs.ready}/${fs.appliers}`,'flux ready',fs.failing?'bad':'good')+
        kpi(fs.defender,'blocked by Defender',fs.defender?'bad':''):'');
}
// One place decides what a console looks like while it works, so every button behaves the
// same: the state line says what is happening and for how long, the button says it is busy,
// and the dot carries the colour. Silence during a slow exec is what made this feel broken.
function setState(stateId,kind,text,ms){
  const st=$(stateId), dot=st.parentElement.querySelector('.d');
  const t = ms==null ? '' : ` · ${(ms/1000).toFixed(1)}s`;
  st.innerHTML = (kind==='run' ? '<span class=spin></span> ' : '') + esc(text) + t;
  st.style.color = kind==='bad' ? 'var(--bad)' : kind==='ok' ? 'var(--ok)' : '';
  if(dot) dot.style.background = kind==='run' ? 'var(--accent)'
    : kind==='ok' ? 'var(--ok)' : kind==='bad' ? 'var(--bad)' : '#2b3a58';
}
// ---- console highlighting ----
// Problem words in red, warnings in amber, healthy states in green, so an error stands out
// in 200 lines of logs. Problem and warning words match any case (ERROR, Error, error);
// healthy words match only Capitalised, so the READY column header stays plain.
// Lines that carry a problem/warning word, or the klog E/W prefix (E1009 12:00:00...), get a
// tinted bar. Backslashes are doubled: PAGE is a plain Python string.
const HL_ISSUE=/\\b(?:(errors?|err|errored|fail|\\w*fail(?:ed|ures?)\\w*|fatal|panic|exception|denied|forbidden|refused|unauthorized|crashloopbackoff|imagepullbackoff|errimagepull|oomkilled|evicted|unhealthy|backoff|notready|invalid)|(warn|warning|warnings|deprecated|pending|timeout|timed out|retry|retrying|terminating|unknown))\\b/gi;
const HL_OK=/\\b(Running|Ready|Succeeded|Completed|Healthy|Normal)\\b/g;
// ---- structured output: -o yaml / -o json / describe / table headers ----
// The format comes from the command (streamTo sets out.dataset.fmt), so a line is coloured
// by what it is, not guessed from its shape. Restrained on purpose: keys in blue, numbers and
// booleans in violet, structure dimmed; plain string values stay in the normal text colour.
function outFormat(cmd){
  if(!cmd)return '';
  const m=cmd.match(/(?:^|\\s)(?:-o|--output)(?:=|\\s*)(yaml|json)(?:\\s|$)/);
  if(m)return m[1];
  if(/^\\s*(?:kubectl|k)\\s+describe\\b/.test(cmd))return 'describe';
  if(/^\\s*(?:kubectl|k)\\s+logs\\b/.test(cmd))return 'logs';
  if(/^\\s*(?:kubectl|k)\\s+(?:get|top)\\b/.test(cmd))return 'table';
  return '';
}
const sp=(c,t)=>`<span class=${c}>${t}</span>`;
function yamlScalar(v){
  if(!v)return v;
  if(/^(?:true|false|null|~|-?\\d+(?:\\.\\d+)?)$/.test(v))return sp('fx-lit',v);
  if(/^[|>][+-]?$/.test(v))return sp('fx-punct',v);
  return sp('fx-str',v);   // quoted or not, a YAML scalar here is a string
}
function hlYaml(line){
  const h=esc(line);
  if(/^\\s*#/.test(line))return sp('fx-comment',h);
  if(/^(?:---|\\.\\.\\.)\\s*$/.test(line))return sp('fx-punct',h);
  const kv=h.match(/^(\\s*)(- )?([^\\s#'"-][^:#]*?|"[^"]*"|'[^']*')(:)(?=\\s|$)(\\s*)(.*)$/);
  if(kv)return kv[1]+(kv[2]?sp('fx-punct',kv[2]):'')+sp('fx-key',kv[3])+sp('fx-punct',kv[4])
    +kv[5]+yamlScalar(kv[6]);
  const li=h.match(/^(\\s*)(- )(.*)$/);
  if(li)return li[1]+sp('fx-punct',li[2])+yamlScalar(li[3]);
  return h;
}
function hlJson(line){
  return esc(line).replace(
    /(\\x22(?:[^\\x22\\\\]|\\\\.)*\\x22)(\\s*:)?|\\b(true|false|null)\\b|(-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)|([{}\\[\\],])/g,
    (m,str,colon,lit,num,p)=>str?(colon?sp('fx-key',str)+sp('fx-punct',colon):sp('fx-str',str))
      :lit?sp('fx-lit',lit):num?sp('fx-lit',num):sp('fx-punct',p));
}
// describe: colour the leading "Key:" and leave the value to the status-word highlighting.
function hlDescribeKey(h){
  return h.replace(/^(\\s*)([A-Z][\\w .\\/-]*?)(:)(?=\\s|$)/,(m,ind,k,c)=>ind+sp('fx-key',k)+sp('fx-punct',c));
}
const TABLE_HEAD=/^[A-Z][A-Z0-9()%-]*(?: [A-Z][A-Z0-9()%-]*)*(?: {2,}[A-Z][A-Z0-9()%-]*(?: [A-Z][A-Z0-9()%-]*)*)+\\s*$/;
function hlLine(line,fmt){
  const h=esc(line);
  if(/^\\$ /.test(line))return `<span class=hl-cmd>${h}</span>`;
  if(/^\\[(exit \\d+|error)\\]/.test(line))return `<span class=hl-bad>${h}</span>`;
  if(/^\\[(done)\\]/.test(line))return `<span class=hl-ok>${h}</span>`;
  if(/^\\[(hint|warn|re-run|run)\\]/.test(line))return `<span class=hl-dim>${h}</span>`;
  // Plain command output only (verify checks, kubectl run/apply): there a denial is THE answer.
  // In a table, describe, YAML or JSON every row may carry one; a page of solid red says nothing,
  // so those keep the normal word-level highlighting.
  if(!fmt){
    // Azure Policy add-on (Gatekeeper): violet, denials and warnings alike, so it never reads
    // as a Defender verdict. Matches the webhook name or the azurepolicy-* constraint prefix.
    // The source badge goes after the indent, so detail lines under a verify check stay aligned.
    const ind=h.match(/^\\s*/)[0], body=h.slice(ind.length);
    if(/validation\\.gatekeeper\\.sh|\\[azurepolicy-/.test(line))
      return `<span class=hl-lazp>${ind}<span class="hl-src azp">AZURE POLICY</span><span class=hl-azp>${body}</span></span>`;
    // Admission denials whole-line red, also indented under a verify check: "denied the request"
    // from the webhook, "denied request" from a policy, and the rule that matched.
    if(/^\\s*(?:Error from server|error: |Verifier rule name:)|\\bdenied (?:the )?request\\b/.test(line)){
      const def=/defender-admission-controller|^\\s*Verifier rule name:/.test(line);
      return `<span class=hl-lbad>${ind}${def?'<span class="hl-src def">DEFENDER</span>':''}<span class=hl-bad>${body}</span></span>`}
  }
  // A kubectl error stays red whatever the format (nothing else is printed then).
  if(/^(?:Error from server|error: )/.test(line))return `<span class=hl-lbad><span class=hl-bad>${h}</span></span>`;
  if(fmt==='yaml')return hlYaml(line);
  if(fmt==='json')return hlJson(line);
  if(fmt==='table'&&TABLE_HEAD.test(line))return sp('fx-head',h);
  // Check reports (verify admission): the whole result line takes the result colour, so a
  // passing check reads green even when it names a deny rule.
  const chk=line.match(/^(✔|✘|!) (.*)$/);
  if(chk){
    const k={'✔':'ok','✘':'bad','!':'warn'}[chk[1]], text=esc(chk[2]);
    return `<span class=hl-l${k}><span class="hl-mark ${k}">${chk[1]}</span> `
      + `<span class=${k==='ok'?'hl-pass':'hl-'+k}>${text}</span></span>`}
  if(/^ +→ /.test(line))return `<span class=hl-hint>${h}</span>`;
  if(/^verify admission controls · /.test(line))return `<span class=hl-title>${h}</span>`;
  const verdict=line.match(/^(GUARDED|PARTLY GUARDED|NOT GUARDED)(: .*)$/);
  if(verdict){
    const k={'GUARDED':'ok','PARTLY GUARDED':'warn','NOT GUARDED':'bad'}[verdict[1]];
    return `<span class="hl-verdict ${k}">${verdict[1]}</span>${esc(verdict[2])}`}
  let issue='';
  if(/^[EF]\\d{4} /.test(line))issue='bad';
  else if(/^W\\d{4} /.test(line))issue='warn';
  let base=fmt==='describe'?hlDescribeKey(h):h;
  if(fmt==='logs'){const lg=hlLogLevel(base); base=lg.html; if(lg.issue&&issue!=='bad')issue=lg.issue}
  const out=outsideTags(base,t=>t.replace(HL_ISSUE,(m,bad)=>{
      const k=bad?'bad':'warn';
      if(issue!=='bad')issue=k;
      return `<span class=hl-${k}>${m}</span>`})
    .replace(HL_OK,'<span class=hl-ok>$1</span>'));
  return issue?`<span class=hl-l${issue}>${out}</span>`:out}
// Run fn over the text between tags only, so a later pass never rewrites a class name.
const outsideTags=(html,fn)=>html.split(/(<[^>]*>)/).map((p,i)=>i%2?p:fn(p)).join('');
// ---- kubectl logs: log levels in every common shape ----
// level=warn, "level":"error", severity: INFO, bare INFO/WRN/ERRO (zap, zerolog, logrus,
// slog, Python), .NET "info:" / "fail:" prefixes, and klog I/W/E. Bare words count only in
// capitals, so "info" or "error" inside a message stays to the issue-word pass. The leading
// timestamp is dimmed so the level is what the eye finds first.
const LOG_LVL={bad:/^(?:error|erro|err|eror|fatal|fata|panic|crit|critical|alert|emerg|emergency|fail|severe)$/i,
  warn:/^(?:warn|warning|wrn)$/i, info:/^(?:info|inf|information|notice)$/i,
  dbg:/^(?:debug|dbg|dbug|trace|trc|trce|verbose|vrb)$/i};
const LOG_TOKEN=/((?:\\blevel|\\blvl|\\bseverity)["\\x27]?\\s*[=:]\\s*["\\x27]?)([A-Za-z]+)|\\b([A-Z]{3,11})\\b|^([a-z]{4})(?=: )/g;
const LOG_TS=/^(\\s*(?:\\[?\\d{4}-\\d{2}-\\d{2}[T ][\\d:.,]+(?:Z|[+-]\\d{2}:?\\d{2})?\\]?|[IWEF]\\d{4} [\\d:.]+|\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d+)?))(?=\\s)/;
function hlLogLevel(h){
  let issue='', ts='';
  const k=h.match(LOG_TS);
  if(k){ts=sp('hl-dim',k[1]); h=h.slice(k[1].length)}
  if(k&&/^\\s*I\\d{4}/.test(k[1]))ts=sp('lv-info',k[1].trim()[0])+sp('hl-dim',k[1].trim().slice(1));
  let first=true;
  h=h.replace(LOG_TOKEN,(m,pre,keyed,bare,net)=>{
    const word=keyed||bare||net;
    const cls=Object.keys(LOG_LVL).find(c=>LOG_LVL[c].test(word));
    if(!cls||(!keyed&&!first&&bare))return m;   // a bare level counts once, the first one
    first=false;
    if(cls==='bad'||cls==='warn')issue=issue==='bad'?'bad':cls;
    return (pre||'')+sp('lv-'+cls,word)});
  return {html:ts+h, issue}}
const hlText=(s,fmt)=>s.split('\\n').map(l=>hlLine(l,fmt)).join('\\n');
// Append a streamed chunk. Complete lines are highlighted once and never touched again; the
// unfinished last line (progress dots, a prompt) waits as plain text in the tail element.
function hlAppend(out,text){
  let tail=out.querySelector('.hl-tail');
  if(!tail){tail=document.createElement('span');tail.className='hl-tail';out.appendChild(tail)}
  const s=tail.textContent+text, nl=s.lastIndexOf('\\n');
  if(nl<0){tail.textContent=s;return}
  tail.insertAdjacentHTML('beforebegin',hlText(s.slice(0,nl+1),out.dataset.fmt));
  tail.textContent=s.slice(nl+1);
}
function hlFlush(out){
  const tail=out.querySelector('.hl-tail');
  if(tail&&tail.textContent){tail.insertAdjacentHTML('beforebegin',hlText(tail.textContent,out.dataset.fmt));tail.textContent=''}
}
function streamTo(id,stateId,btn,url,body){
  const out=$(id), b=btn?$(btn):null, label=b?b.textContent:'', t0=Date.now();
  out.textContent=''; out.dataset.busy='1';
  out.dataset.fmt=outFormat(body&&body.cmd);
  if(id==='out'){const f=$('cmdfmt'), show=['yaml','json'].includes(out.dataset.fmt);
    f.hidden=!show; f.textContent=show?out.dataset.fmt:''; $('cmdcopy').hidden=false}
  setState(stateId,'run','running…',0);
  const tick=setInterval(()=>setState(stateId,'run','running…',Date.now()-t0),250);
  // The console button keeps its run label; the state line beside it shows the progress.
  if(b){b.disabled=true; if(btn!=='cmdbtn')b.textContent='… running';}
  const stop=()=>{clearInterval(tick); out.dataset.busy=''; if(b){b.disabled=false; b.textContent=label;}};
  fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})
   .then(async r=>{
     const rd=r.body.getReader(), dec=new TextDecoder();
     let bytes=0, chars=0;
     for(;;){
       const{done,value}=await rd.read(); if(done)break;
       bytes+=value.length;
       const text=dec.decode(value,{stream:true});
       chars+=text.length;
       hlAppend(out,text);
       if(chars>MAX_CONSOLE_CHARS){
         // rebuilt from the plain text, so the kept part is highlighted again from scratch
         const keep=out.textContent.slice(-MAX_CONSOLE_CHARS);
         out.textContent='';
         hlAppend(out,'…trimmed…\\n'+keep);
         chars=keep.length;
       }
       // Only chase the bottom while the reader is already there, so scrolling back
       // through output is not yanked away by the next chunk.
       if(out.scrollHeight-out.scrollTop-out.clientHeight<80)out.scrollTop=out.scrollHeight;
     }
     clearInterval(tick);
     hlFlush(out);
     const ms=Date.now()-t0, txt=out.textContent;
     if(!r.ok) return setState(stateId,'bad',r.status===403?'refused':`HTTP ${r.status}`,ms);
     if(!bytes){ out.textContent='(no output)'; return setState(stateId,'ok','finished · empty',ms); }
     const m=txt.match(/\\[exit (\\d+)\\]/);
     if(m) return setState(stateId,'bad',`exit ${m[1]}`,ms);
     if(/\\[error\\]/.test(txt)) return setState(stateId,'bad','failed',ms);
     setState(stateId,'ok','finished',ms);
   })
   .catch(e=>{clearInterval(tick); hlAppend(out,'\\n[error] '+e+'\\n'); setState(stateId,'bad','failed',Date.now()-t0)})
   .finally(stop);
}
function runCmd(e){
  if(e)e.preventDefault();
  const cmd=$('cmd').value.trim();
  if(!cmd){setState('cmdstate','bad','type a command first'); return}
  streamTo('out','cmdstate','cmdbtn','/api/exec',{cmd:cmd});
}
// Every blade gets the same expand control, added here rather than in each header so the
// markup stays readable and a new card cannot forget it.
function toggleExpand(card){
  if(card.classList.contains('collapsed'))setCollapsed(card,false);
  const on=card.classList.toggle('expanded');
  document.body.classList.toggle('locked',on);
  let back=$('backdrop');
  if(on&&!back){
    back=document.createElement('div');
    back.id='backdrop'; back.className='backdrop';
    back.onclick=()=>toggleExpand(card);
    document.body.appendChild(back);
  }else if(!on&&back){back.remove()}
  // The expand button, not the hide/show one: both carry .exp, and hide/show comes first.
  const btn=card.querySelector(':scope > h2 > .exp:not(.col)');
  if(btn){btn.textContent=on?'\u2715 close':'\u2922 expand';
          btn.title=on?'back to the dashboard (esc)':'expand this blade to the full page'}
  if(on)card.scrollTop=0;
}
// ---- collapse: hide blades you do not need right now ----
// Remembered per browser (localStorage), keyed by the blade title. Storage can be blocked or
// throw (private window, cleared site data), so every access is guarded and the page works
// without it.
const COLLAPSE_KEY='panel.collapsed';
function bladeKey(card){
  const h=card.querySelector(':scope > h2');
  return h&&h.firstChild?h.firstChild.textContent.trim():'';
}
function loadCollapsed(){
  try{return new Set(JSON.parse(localStorage.getItem(COLLAPSE_KEY)||'[]'))}catch(e){return new Set()}
}
function saveCollapsed(set){
  try{localStorage.setItem(COLLAPSE_KEY,JSON.stringify([...set]))}catch(e){}
}
function setCollapsed(card,on){
  card.classList.toggle('collapsed',on);
  const btn=card.querySelector(':scope > h2 > .col');
  if(btn){btn.textContent=on?'\u25b8 show':'\u25be hide';
          btn.title=on?'show this blade again':'collapse this blade to its title bar'}
  const set=loadCollapsed(), key=bladeKey(card);
  if(key){on?set.add(key):set.delete(key); saveCollapsed(set)}
}
// Header buttons: collapse or show every blade at once (remembered like the per-blade toggle).
// A blade open in full-page view is closed first, so collapsing never hides the overlay content.
function collapseAll(on){
  const open=document.querySelector('section.card.expanded');
  if(open)toggleExpand(open);
  document.querySelectorAll('section.card').forEach(c=>setCollapsed(c,on));
  if(!on)window.scrollTo({top:0,behavior:'smooth'});
}
function addExpandButtons(){
  const hidden=loadCollapsed();
  document.querySelectorAll('section.card > h2').forEach(h=>{
    const c=document.createElement('button');
    c.className='exp col'; c.type='button';
    c.style.marginLeft=h.querySelector('.muted')?'8px':'auto';
    c.onclick=()=>{const card=h.parentElement;
      // Hiding a full-page blade would leave the page locked behind an empty overlay.
      if(card.classList.contains('expanded'))toggleExpand(card);
      setCollapsed(card,!card.classList.contains('collapsed'))};
    h.appendChild(c);
    const b=document.createElement('button');
    b.className='exp'; b.type='button';
    b.textContent='\u2922 expand';
    b.title='expand this blade to the full page';
    b.style.marginLeft='6px';
    b.onclick=()=>toggleExpand(h.parentElement);
    h.appendChild(b);
    const card=h.parentElement;
    // A click on the title bar toggles the blade: shows a collapsed one, hides an open one.
    // A collapsed blade is only its title bar, so a click anywhere on it opens it. Controls in
    // the bar keep their own action.
    h.addEventListener('click',e=>{
      if(e.target.closest('button,a,input,select,textarea,label'))return;
      if(card.classList.contains('expanded'))toggleExpand(card);
      setCollapsed(card,!card.classList.contains('collapsed'))});
    setCollapsed(card,hidden.has(bladeKey(card)));
  });
}
addEventListener('DOMContentLoaded',addExpandButtons);
addEventListener('keydown',e=>{
  if(e.key!=='Escape')return;
  if($('rowmenu')){closeMenu();return}
  const open=document.querySelector('section.card.expanded');
  if(open)toggleExpand(open);
});

// Filtering is local to rows already fetched, so it can run on every keystroke.
addEventListener('DOMContentLoaded',()=>{
  const q=$('q');
  if(!q)return;
  let raf=0;
  q.addEventListener('input',()=>{
    if(raf)return;
    raf=requestAnimationFrame(()=>{raf=0;renderPods()});
  });
  q.addEventListener('keydown',e=>{if(e.key==='Escape')clearFilter()});
});

// Ctrl/Cmd+Enter runs from anywhere in the box; plain Enter already submits the form.
addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==='Enter'&&!$('cmdbtn').disabled) runCmd();
});
function copyOut(id){
  const t=$(id).textContent;
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(
    ()=>flash(id,'copied'), ()=>flash(id,'copy failed'));
}
// Copy just the command output (YAML, JSON, tables, logs): drop the "$ kubectl ..." echo and
// its blank line, and the [exit n] / [error] / [done] markers the panel appends.
function copyDoc(){
  const lines=$('out').textContent.split('\\n');
  if(lines.length&&/^\\$ /.test(lines[0]))lines.splice(0,lines[1]===''?2:1);
  while(lines.length&&(/^\\[(exit \\d+|error|done)\\]/.test(lines[lines.length-1])||!lines[lines.length-1].trim()))lines.pop();
  const t=lines.join('\\n')+'\\n', b=$('cmdcopy');
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(
    ()=>{b.textContent='✓ copied';setTimeout(()=>{b.textContent='⧉ copy'},1200)},
    ()=>flash('out','copy failed'));
}
function clearOut(id,stateId){$(id).textContent=''; setState(stateId,'','ready');
  if(id==='out'){$('cmdfmt').hidden=true; $('cmdcopy').hidden=true}}
function flash(id,msg){
  // the status text, not the format pill or the copy button that may follow it in the bar
  const bar=$(id).parentElement.querySelector('.bar span:not(.d):not(.fmt)'), old=bar.innerHTML;
  bar.innerHTML=esc(msg); setTimeout(()=>{bar.innerHTML=old},1200);
}
const picked=()=>[...document.querySelectorAll('.scn:checked')].map(c=>c.value);
const pickAll=()=>document.querySelectorAll('.scn').forEach(c=>c.checked=true);
const pickNone=()=>document.querySelectorAll('.scn').forEach(c=>c.checked=false);
function runSim(){
  const sc=picked();
  if(!sc.length){$('simout').textContent='Pick at least one scenario first.';return}
  streamTo('simout','simstate','simbtn','/api/sim',{scenarios:sc,privileged:$('simpriv').checked})}
async function loadScenarios(){
  const d=await j('/api/sim/scenarios');
  $('simmeta').textContent=d.configured?`${d.image} → ns ${d.namespace}`:'ALERT_SIM_IMAGE not set — build with `make app`';
  $('simpick').innerHTML=Object.entries(d.groups).map(([g,l])=>
    `<div class=grp><div class=gt>${esc(g)}</div><div class=scns>`+
     l.map(x=>`<label class=scn-l><input type=checkbox class=scn value="${esc(x)}"${g.startsWith('quick')?' checked':''}><span class=mono>${esc(x)}</span></label>`).join('')+
    `</div></div>`).join('')}
async function chat(e){e.preventDefault();
  const st=$('chatstate'); st.innerHTML='<span class=spin></span> thinking…';
  const r=await fetch('/api/chat',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({mode:$('cmode').value,prompt:$('prompt').value})});
  const d=await r.json();
  $('chatout').textContent = d.error?'error: '+d.error
    : d.blocked?'⛔ blocked by content filtering / Prompt Shields\\n\\n'+d.detail+'\\n\\n'+d.note
    : (d.reply??d.note??JSON.stringify(d,null,2))+'\\n\\n— as '+(d.user??'?')+' via '+(d.model??'?');
  st.textContent=d.blocked?'blocked (that is the demo)':'done'}
let timer=null;
$('auto').addEventListener('change',e=>{clearInterval(timer);
  if(e.target.checked)timer=setInterval(()=>{
    if(document.hidden||$('rowmenu')||document.activeElement===$('q'))return;
    refresh();
  },10000)});
refresh(); loadScenarios();
</script>"""


def manual_scenarios():
    """One-click "deploy it by hand" beats: real pods (not dry runs) created through the console,
    so admission answers exactly as it would for an engineer with kubectl. Every pod is named
    manual-* and labelled origin=manual, so one cleanup command removes them all."""
    acr = ACR_LOGIN_SERVER or "<acr>.azurecr.io"
    privileged = json.dumps({"spec": {"containers": [{
        "name": "manual-privileged-root", "image": MISCONFIG_TEST_IMAGE,
        "command": ["sleep", "infinity"],
        "securityContext": {"privileged": True, "runAsUser": 0,
                            "allowPrivilegeEscalation": True}}]}}, separators=(",", ":"))
    # The counter-beat: a restricted pod in the same gated namespace is admitted. It needs the
    # scanned, CVE-free Alpine from ACR (x-mdc-blocked also denies unscanned images); the misconfig
    # workflow points :latest at the tag Defender scanned.
    restricted = json.dumps({"spec": {"containers": [{
        "name": "manual-restricted", "image": f"{acr}/misconfig-alpine:latest",
        "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                      "limits": {"cpu": "50m", "memory": "32Mi"}},
        "securityContext": RESTRICTED_SECURITY_CONTEXT}]}}, separators=(",", ":"))
    run = "kubectl run {name} -n {ns} --restart=Never --labels=origin=manual --image={img}"
    return {
        "blocked": run.format(name="manual-webapp-blocked", ns="x-mdc-blocked",
                              img=f"{acr}/aks-webapp:latest"),
        "allowed": run.format(name="manual-webapp-allowed", ns="x-mdc-allowed",
                              img=f"{acr}/aks-webapp:latest"),
        "misconfig": run.format(name="manual-privileged-root", ns="x-mdc-blocked",
                                img=MISCONFIG_TEST_IMAGE) + f" --overrides='{privileged}'",
        "restricted": run.format(name="manual-restricted", ns="x-mdc-blocked",
                                 img=f"{acr}/misconfig-alpine:latest") + f" --overrides='{restricted}'",
        "status": "kubectl get pods -A -l origin=manual -o wide",
        "cleanup": "kubectl delete pods -A -l origin=manual --ignore-not-found",
    }


@app.get("/")
def home():
    return render_template_string(
        PAGE, aks=AKS_NAME, mode=KUBECTL_MODE, library=command_library(), manual=manual_scenarios(),
        mining_cmd=MINING_DRILL_CMD, mining_pool=MINING_POOL, conns_cmd=CONNS_CMD,
        foundry=bool(FOUNDRY_ENDPOINT), model=AI_MODEL_NAME,
        authmode=("basic" if BASIC_ON else "entra"),
        authhint=("HTTP Basic enforced by the app (lab fallback: no MFA, no Conditional Access)"
                  if BASIC_ON else
                  "Container Apps EasyAuth with Microsoft Entra, scoped to assigned users"))


@app.get("/healthz")
def healthz():
    return "ok", 200


def _aks_webapp_url():
    """Public URL of the aks-webapp: the LoadBalancer address of x-mdc-allowed/Service webapp."""
    api, _batch, _ = k8s()
    svc = api.read_namespaced_service("webapp", "x-mdc-allowed")
    ingress = (svc.status.load_balancer.ingress or []) if svc.status.load_balancer else []
    host = next((i.ip or i.hostname for i in ingress if i.ip or i.hostname), "")
    if not host:
        raise RuntimeError("Service x-mdc-allowed/webapp has no LoadBalancer address yet")
    port = next((p.port for p in svc.spec.ports or [] if p.port), 80)
    return f"http://{host}" + ("" if port == 80 else f":{port}")


@app.get("/api/aks-webapp")
def api_aks_webapp():
    try:
        return jsonify({"url": _aks_webapp_url()})
    except Exception as e:                                   # noqa: BLE001
        return jsonify({"url": "", "error": f"{type(e).__name__}: {str(e)[:200]}"})


@app.get("/api/connections")
def api_connections():
    """Heartbeat + synthetic Blob state as reported by the aks-webapp pod itself."""
    import requests
    try:
        url = _aks_webapp_url()
        d = requests.get(f"{url}/api/data", timeout=(3, 5)).json()
        d["url"] = url
        return jsonify(d)
    except Exception as e:                                   # noqa: BLE001
        # Fall back to this process's own (normally disabled) state, with the reason.
        d = json.loads(json.dumps(_connections))
        d["error"] = f"aks-webapp unreachable - {type(e).__name__}: {str(e)[:160]}"
        return jsonify(d)


@app.get("/api/overview")
def api_overview():
    try:
        api, _batch, _ = k8s()
        # Nodes are cluster-scoped and the Azure RBAC Reader role does not cover them, so a
        # 403 here is a permissions gap, not a broken cluster: report it and keep going.
        nodes_error = None
        try:
            nodes = api.list_node().items
        except Exception as e:                               # noqa: BLE001
            nodes, nodes_error = [], (
                f"{type(e).__name__}: node list denied - apply "
                "app/k8s/05-panel-node-reader.yaml (make grant-panel)"
                if "403" in str(e) else f"{type(e).__name__}: {e}")
        ns = [n.metadata.name for n in api.list_namespace().items]
        return jsonify(
            cluster=AKS_NAME or AKS_FQDN,
            version=(nodes[0].status.node_info.kubelet_version if nodes else "unknown"),
            node_count=len(nodes),
            nodes_error=nodes_error,
            namespaces=sorted(ns),
            nodes=[{"name": n.metadata.name,
                    "status": next((c.type for c in n.status.conditions
                                    if c.type == "Ready" and c.status == "True"), "NotReady"),
                    "version": n.status.node_info.kubelet_version,
                    "os": n.status.node_info.os_image} for n in nodes])
    except Exception as e:                                   # noqa: BLE001
        return jsonify(error=f"{type(e).__name__}: {e}"), 500


# Defender alerts for THIS cluster, read from the Defender alerts REST API at resource-group
# scope. Not Azure Resource Graph: ARG masks the sensitive alert fields (CompromisedEntity,
# CommandLine come back as "*****"), which hides exactly what the demo wants to show - the
# process, the container, the domain. The REST API returns them in clear to the panel's
# identity, which holds Security Reader on the lab's resource group and nothing wider.
ALERTS_API_VERSION = os.environ.get("ALERTS_API_VERSION", "2022-01-01")
ALERT_LIMIT = 50

# entity type -> how to label it. The cluster itself is on every alert; azure-resource
# repeats K8s-cluster, so that one is the only type left out.
_ENTITY_SKIP = {"azure-resource"}


def _subscription_id():
    """The subscription the cluster lives in, taken from its resource ID."""
    parts = AKS_RESOURCE_ID.strip("/").split("/")
    return parts[1] if len(parts) > 1 and parts[0].lower() == "subscriptions" else ""


def _resource_group():
    """The cluster's resource group, taken from its resource ID."""
    parts = AKS_RESOURCE_ID.strip("/").split("/")
    return parts[3] if len(parts) > 3 and parts[2].lower() == "resourcegroups" else ""


def _entity_label(e):
    """One readable value for an alert entity, by type."""
    t = e.get("type", "")
    image = e.get("imageFile") or {}
    if t == "process":
        return e.get("commandLine") or image.get("name") or e.get("processId", "")
    if t == "file":
        return "/".join(x for x in (e.get("directory"), e.get("name")) if x)
    if t == "dns":
        return e.get("domainName", "")
    if t == "ip":
        return e.get("address", "")
    if t == "host":
        return e.get("hostName") or e.get("netBiosName", "")
    if t == "container-image":
        return e.get("imageId") or e.get("name", "")
    if t == "account":
        return e.get("name") or e.get("aadUserId", "")
    return e.get("name") or e.get("friendlyName") or e.get("id", "")


def _alert_entities(entities):
    """Every distinct entity on an alert as (type, value). '$ref' items repeat an object
    already listed, so they are dropped; nested objects are listed on their own anyway."""
    out, seen = [], set()
    for e in entities or []:
        t = e.get("type")
        if not t or t in _ENTITY_SKIP:
            continue
        v = str(_entity_label(e) or "").strip()
        if v and (t, v) not in seen:
            seen.add((t, v))
            out.append({"type": t, "value": v})
    return out


@app.get("/api/alerts")
def api_alerts():
    sub, rg = _subscription_id(), _resource_group()
    if not sub or not rg:
        return jsonify(alerts=[], note="AKS_RESOURCE_ID is not set, so the resource group "
                                       "to query is unknown"), 200
    try:
        import requests
        from azure.identity import DefaultAzureCredential
        token = DefaultAzureCredential().get_token(f"{ARM_ENDPOINT}/.default").token
        url = (f"{ARM_ENDPOINT}/subscriptions/{sub}/resourceGroups/{rg}"
               f"/providers/Microsoft.Security/alerts?api-version={ALERTS_API_VERSION}")
        cluster = AKS_RESOURCE_ID.lower()
        alerts = []
        for _ in range(10):                                  # follow nextLink, bounded
            r = requests.get(url, timeout=30, headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 403:
                return jsonify(alerts=[], error="denied by Azure RBAC: the panel identity needs "
                                                "Security Reader on the resource group"), 200
            r.raise_for_status()
            body = r.json()
            for a in body.get("value", []):
                p = a.get("properties", {})
                if str(p.get("status", "")).lower() in ("dismissed", "resolved"):
                    continue
                ids = str(p.get("resourceIdentifiers", "")).lower()
                entity = str(p.get("compromisedEntity", ""))
                if cluster not in ids and AKS_NAME.lower() not in entity.lower():
                    continue
                alerts.append({
                    "alert": p.get("alertDisplayName", ""), "severity": p.get("severity", ""),
                    "status": p.get("status", ""), "started": p.get("startTimeUtc", ""),
                    "entity": entity, "intent": p.get("intent", ""),
                    "description": p.get("description", ""),
                    "entities": _alert_entities(p.get("entities")),
                })
            url = body.get("nextLink")
            if not url:
                break
        alerts.sort(key=lambda x: x["started"], reverse=True)
        return jsonify(alerts=alerts[:ALERT_LIMIT], cluster=AKS_NAME)
    except Exception as e:                                   # noqa: BLE001
        return jsonify(alerts=[], error=f"{type(e).__name__}: {e}"), 200


# ---- Flux GitOps state ------------------------------------------------------
# Flux reports "health check failed ... timeout waiting for Deployment/x-mdc-blocked/webapp",
# which says THAT the rollout failed but not WHY. The why is the admission webhook's denial,
# and it only lives in two places nobody looks: the ReplicaSet's ReplicaFailure condition
# (current state, survives as long as the ReplicaSet) and the FailedCreate Events (history
# with a count, expire after ~1h). This view reads both and pins the denial to the
# Kustomization that owns the workload, so the blade can say "blocked by Defender" outright.
#
# RBAC: Flux objects are custom resources the Azure RBAC Reader role does not cover -
# app/k8s/06-panel-flux-reader.yaml grants them. ReplicaSets and Events need nothing extra.
FLUX_KINDS = [  # (kind, group, plural, versions newest first)
    ("Kustomization", "kustomize.toolkit.fluxcd.io", "kustomizations", ("v1", "v1beta2")),
    ("GitRepository", "source.toolkit.fluxcd.io", "gitrepositories", ("v1", "v1beta2")),
    ("OCIRepository", "source.toolkit.fluxcd.io", "ocirepositories", ("v1", "v1beta2")),
    ("HelmRelease", "helm.toolkit.fluxcd.io", "helmreleases", ("v2", "v2beta2", "v2beta1")),
]
FLUX_NS = os.environ.get("FLUX_NAMESPACE", "flux-system")
FLUX_CONFIG = os.environ.get("FLUX_CONFIG_NAME", "demo-apps")
_WEBHOOK_DENIAL = re.compile(r'admission webhook "([^"]+)" denied the request:?\s*(.*)', re.S)
_VAP_DENIAL = re.compile(r"ValidatingAdmissionPolicy '([^']+)' with binding '([^']+)' "
                         r"denied request:?\s*(.*)", re.S)
_RULE_NAME = re.compile(r"rule name:\s*([^\s,;]+)", re.I)
# Gatekeeper prefixes each violation with its constraint, e.g. [azurepolicy-k8sazurev2noprivilege-1a2b].
_CONSTRAINT = re.compile(r"\[([a-z0-9][a-z0-9.-]*)\]")


def _ts(value):
    """ISO string for a k8s timestamp, whether the client gave a datetime or a string."""
    if value is None:
        return ""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


def _parse_denial(message):
    """Classify an admission refusal. None when the message is not one."""
    m = _WEBHOOK_DENIAL.search(message or "")
    if m:
        hook, detail = m.group(1), m.group(2).strip()
        if "gatekeeper" in hook.lower():
            # Azure Policy add-on: its own control, kept apart from Defender's gate.
            rule = _CONSTRAINT.search(detail)
            return {"gate": "azure-policy", "by": hook, "rule": rule.group(1) if rule else "",
                    "detail": detail}
        rule = _RULE_NAME.search(detail)
        return {"gate": "defender" if "defender" in hook.lower() else "webhook",
                "by": hook, "rule": rule.group(1) if rule else "", "detail": detail}
    m = _VAP_DENIAL.search(message or "")
    if m:
        return {"gate": "policy", "by": f"ValidatingAdmissionPolicy {m.group(1)}",
                "rule": m.group(2), "detail": m.group(3).strip()}
    return None


def _flux_list(custom, group, plural, versions):
    """Items of one Flux kind across all namespaces, trying served API versions in turn.
    Returns (items, error); a kind whose CRD is not installed is simply empty."""
    from kubernetes.client.exceptions import ApiException
    for version in versions:
        try:
            return custom.list_cluster_custom_object(group, version, plural).get("items", []), None
        except ApiException as e:
            if e.status == 404:
                continue
            if e.status == 403:
                return [], (f"{plural}.{group}: denied - apply app/k8s/06-panel-flux-reader.yaml "
                            "(make grant-panel)")
            return [], f"{plural}.{group}: {e.status} {e.reason}"
    return [], None


def _flux_object(kind, obj):
    """The fields the blade shows, the same shape for every Flux kind."""
    meta, spec, status = obj.get("metadata", {}), obj.get("spec", {}), obj.get("status", {})
    ready = next((c for c in status.get("conditions", []) if c.get("type") == "Ready"), {})
    src = spec.get("sourceRef") or (spec.get("chart", {}).get("spec", {}).get("sourceRef")) or {}
    workloads, namespaces = [], set()
    for entry in (status.get("inventory") or {}).get("entries", []):
        # id is <namespace>_<name>_<group>_<kind>; cluster-scoped objects have no namespace
        parts = entry.get("id", "").split("_")
        if len(parts) < 4:
            continue
        ns, name, ikind = parts[0], "_".join(parts[1:-2]), parts[-1]
        if ns:
            namespaces.add(ns)
        if ikind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
            workloads.append({"namespace": ns, "kind": ikind, "name": name})
    return {
        "kind": kind, "namespace": meta.get("namespace", ""), "name": meta.get("name", ""),
        "ready": ready.get("status", "Unknown"), "reason": ready.get("reason", ""),
        "message": ready.get("message", ""), "since": ready.get("lastTransitionTime", ""),
        "suspended": bool(spec.get("suspend")),
        "revision": (status.get("lastAppliedRevision")
                     or (status.get("artifact") or {}).get("revision", "")),
        "attempted": status.get("lastAttemptedRevision", ""),
        "path": spec.get("path", ""), "url": spec.get("url", ""),
        "source": f"{src.get('kind', '')}/{src.get('name', '')}" if src else "",
        "interval": spec.get("interval", ""),
        "dependsOn": [d.get("name", "") for d in spec.get("dependsOn", [])],
        "workloads": workloads, "namespaces": sorted(namespaces),
    }


def _admission_denials(core, apps):
    """Every workload whose pods the API server refused, keyed by owner.

    ReplicaSet conditions give the CURRENT state; FailedCreate Events add the count and the
    first/last time (and cover Jobs, DaemonSets and StatefulSets, which have no condition)."""
    denials = {}

    for rs in apps.list_replica_set_for_all_namespaces().items:
        if not rs.spec.replicas:
            continue      # an old ReplicaSet scaled to zero is history, not a blocked rollout
        cond = next((c for c in (rs.status.conditions or [])
                     if c.type == "ReplicaFailure" and c.status == "True"), None)
        parsed = _parse_denial(cond.message if cond else "")
        if not parsed:
            continue
        owner = next((o for o in (rs.metadata.owner_references or [])
                      if o.kind == "Deployment"), None)
        key = (rs.metadata.namespace, "ReplicaSet", rs.metadata.name)
        denials[key] = dict(parsed, namespace=rs.metadata.namespace,
                            object=f"ReplicaSet/{rs.metadata.name}",
                            workload=(f"Deployment/{owner.name}" if owner
                                      else f"ReplicaSet/{rs.metadata.name}"),
                            images=[c.image for c in rs.spec.template.spec.containers],
                            count=1, first=_ts(cond.last_transition_time),
                            last=_ts(cond.last_transition_time), active=True)

    for ev in core.list_event_for_all_namespaces(field_selector="reason=FailedCreate").items:
        parsed = _parse_denial(ev.message)
        if not parsed:
            continue
        io = ev.involved_object
        key = (io.namespace, io.kind, io.name)
        count = (ev.series.count if ev.series else None) or ev.count or 1
        first = _ts(ev.first_timestamp or ev.event_time)
        last = _ts((ev.series.last_observed_time if ev.series else None)
                   or ev.last_timestamp or ev.event_time)
        d = denials.get(key)
        if d:
            d["count"] = max(d["count"], count)
            d["first"] = min(filter(None, (d["first"], first)), default="")
            d["last"] = max(d["last"], last)
        else:
            # Only events: the workload may be fixed since, or it has no ReplicaSet condition.
            denials[key] = dict(parsed, namespace=io.namespace, object=f"{io.kind}/{io.name}",
                                workload=f"{io.kind}/{io.name}", images=[], count=count,
                                first=first, last=last, active=False)
    return sorted(denials.values(), key=lambda d: d["last"], reverse=True)


def _flux_events(core, kinds):
    """Recent Events the Flux controllers raised on their own objects, newest first."""
    out = []
    for ev in core.list_namespaced_event(FLUX_NS).items:
        io = ev.involved_object
        if io.kind not in kinds:
            continue
        out.append({"type": ev.type, "reason": ev.reason, "object": f"{io.kind}/{io.name}",
                    "message": ev.message or "", "count": ev.count or 1,
                    "last": _ts(ev.last_timestamp or ev.event_time)})
    return sorted(out, key=lambda e: e["last"], reverse=True)[:40]


@app.get("/api/flux")
def api_flux():
    try:
        c, kclient = k8s_api_client()
        core, apps, custom = kclient.CoreV1Api(c), kclient.AppsV1Api(c), kclient.CustomObjectsApi(c)
        errors, objects = [], []
        for kind, group, plural, versions in FLUX_KINDS:
            items, err = _flux_list(custom, group, plural, versions)
            if err:
                errors.append(err)
            objects += [_flux_object(kind, o) for o in items]

        try:
            denials = _admission_denials(core, apps)
        except Exception as e:                               # noqa: BLE001
            denials = []
            errors.append(f"admission denials: {type(e).__name__}: {e}")
        try:
            events = _flux_events(core, {k for k, *_ in FLUX_KINDS})
        except Exception as e:                               # noqa: BLE001
            events = []
            errors.append(f"flux events: {type(e).__name__}: {e}")

        # Pin each denial to the Flux object that applied the workload. Exact matches only:
        # a namespace match would blame Flux for a Job the panel itself started. A ReplicaSet
        # known only from its Events is <deployment>-<pod-template-hash>, so match the prefix.
        appliers = [o for o in objects if o["kind"] in ("Kustomization", "HelmRelease")]
        for d in denials:
            kind, _, name = d["workload"].partition("/")
            owner = None
            for o in appliers:
                for w in o["workloads"]:
                    if w["namespace"] != d["namespace"]:
                        continue
                    if (w["kind"], w["name"]) == (kind, name) or (
                            kind == "ReplicaSet" and w["kind"] == "Deployment"
                            and name.startswith(w["name"] + "-")):
                        owner, d["workload"] = o, f"{w['kind']}/{w['name']}"
                        break
                if owner:
                    break
            d["flux"] = f"{owner['kind']}/{owner['name']}" if owner else ""
            if owner and d["active"]:
                owner.setdefault("denials", []).append(d["workload"])

        appliers_failing = [o for o in appliers if o["ready"] == "False" and not o["suspended"]]
        return jsonify(
            objects=objects, denials=denials, events=events, errors=errors,
            namespace=FLUX_NS, config=FLUX_CONFIG,
            summary={
                "appliers": len(appliers),
                "ready": sum(o["ready"] == "True" for o in appliers),
                "failing": len(appliers_failing),
                "blocked": sum(bool(o.get("denials")) for o in appliers_failing),
                "suspended": sum(o["suspended"] for o in appliers),
                "denials": sum(d["active"] for d in denials),
                "defender": sum(d["active"] and d["gate"] == "defender" for d in denials),
                "azure_policy": sum(d["active"] and d["gate"] == "azure-policy" for d in denials),
            })
    except Exception as e:                                   # noqa: BLE001
        return jsonify(error=f"{type(e).__name__}: {e}"), 500


@app.get("/api/commands")
def api_commands():
    """The same library the console shows, for scripts driving /api/exec with the API key."""
    return jsonify(defenderNamespace=DEFENDER_NS,
                   groups=[{"group": g, "commands": [{"label": lbl, "cmd": cmd}
                                                     for lbl, cmd in items]}
                           for g, items in command_library()])


@app.get("/api/pods")
def api_pods():
    ns = request.args.get("ns")
    try:
        api, _batch, _ = k8s()
        items = (api.list_namespaced_pod(ns) if ns else api.list_pod_for_all_namespaces()).items
        def containers_of(pod):
            # Status carries readiness and restarts, spec carries the image. A pod that has
            # not started yet has no status entry, so spec is the source of truth for names.
            status = {cs.name: cs for cs in (pod.status.container_statuses or [])}
            out = []
            for c in (pod.spec.init_containers or []):
                cs = status.get(c.name)
                out.append({"name": c.name, "image": c.image, "init": True,
                            "ready": bool(cs and cs.ready),
                            "restarts": (cs.restart_count if cs else 0) or 0})
            for c in (pod.spec.containers or []):
                cs = status.get(c.name)
                out.append({"name": c.name, "image": c.image, "init": False,
                            "ready": bool(cs and cs.ready),
                            "restarts": (cs.restart_count if cs else 0) or 0})
            return out

        return jsonify(pods=[{
            "namespace": p.metadata.namespace, "name": p.metadata.name,
            "status": p.status.phase,
            "restarts": sum((cs.restart_count or 0) for cs in (p.status.container_statuses or [])),
            "image": (p.spec.containers[0].image if p.spec.containers else ""),
            "node": p.spec.node_name or "",
            "containers": containers_of(p),
        } for p in items])
    except Exception as e:                                   # noqa: BLE001
        return jsonify(error=f"{type(e).__name__}: {e}"), 500


def _errors_as_output(gen):
    """A streamed response has already sent its headers, so an exception raised mid-iteration
    cannot become an HTTP error - it just truncates the stream and the console looks frozen.
    Surface the failure as text instead, which is what you want live on stage."""
    try:
        yield from gen
    except Exception as e:                                   # noqa: BLE001
        yield (f"\n\n[error] {type(e).__name__}: {e}\n"
               "[hint] check: the cluster is reachable, the app identity has the Azure RBAC "
               "role (make grant-panel), and the kubectl-runner pod is running in demo-ops.\n")


def _exec_stream(argv):
    """Exec argv in the kubectl-runner pod, yielding output as it arrives."""
    from kubernetes.stream import stream as kstream
    api, _batch, _ = k8s()
    pod = runner_pod(api)
    yield f"$ {' '.join(argv)}\n\n"
    resp = kstream(api.connect_get_namespaced_pod_exec, pod, RUNNER_NS,
                   command=argv, stderr=True, stdout=True, stdin=False, tty=False,
                   _preload_content=False)
    while resp.is_open():
        resp.update(timeout=1)
        if resp.peek_stdout():
            yield resp.read_stdout()
        if resp.peek_stderr():
            yield resp.read_stderr()
    resp.close()
    rc = resp.returncode
    yield f"\n[exit {rc}]\n" if rc else "\n[done]\n"


# ---- pipes in the console ----------------------------------------------------
# There is no shell, on purpose: with one, `kubectl get pods; <anything>` would walk past the
# read-only allowlist. So `|` is implemented HERE. The first stage is exec'd in the runner
# exactly as before and judged by allowed(); every later stage is a filter the panel applies
# to that command's stdout in Python. Nothing after a | executes anywhere - a filter can only
# drop, count or reorder lines. stderr skips the pipe, as it does in a shell.
PIPE_FILTER_HELP = "grep/egrep (-i -v -c -n -w -E -F -e), head/tail (-n N), wc (-l -w -c), sort (-r -n -u -f -k N), uniq (-c -d -u -i), column (-t)"


def split_pipeline(raw):
    """'k get pods -A | grep kube' -> [['k', 'get', 'pods', '-A'], ['grep', 'kube']].
    A quoted | ('a|b') stays part of its word; a line without | parses exactly as before."""
    if "|" not in raw:
        return [shlex.split(raw)]
    lex = shlex.shlex(raw, posix=True, punctuation_chars="|")
    lex.whitespace_split = True
    stages = [[]]
    for tok in lex:
        if tok == "|":
            stages.append([])
        elif tok and set(tok) == {"|"}:
            raise ValueError(f"'{tok}' is not supported - only a single | between commands")
        else:
            stages[-1].append(tok)
    if any(not st for st in stages):
        raise ValueError("empty command next to |")
    return stages


_BRE_SWAP = set("|+?(){}")


def _bre_to_re(pattern):
    r"""grep without -E speaks BRE: \| \+ \( are the operators and bare | + ( are literal.
    Python re is the other way round, so swap the escaping of exactly those characters."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            n = pattern[i + 1]
            out.append(n if n in _BRE_SWAP else c + n)
            i += 2
            continue
        out.append("\\" + c if c in _BRE_SWAP else c)
        i += 1
    return "".join(out)


def _grep(args, extended=False):
    opts, patterns, rest = set(), [], list(args)
    while rest and rest[0].startswith("-") and len(rest[0]) > 1:
        a = rest.pop(0)
        if a == "--":
            break
        if a == "-e":
            if not rest:
                raise ValueError("grep: -e needs a pattern")
            patterns.append(rest.pop(0))
            continue
        for ch in a[1:]:
            if ch not in "ivcnwEF":
                raise ValueError(f"grep: -{ch} is not supported here ({PIPE_FILTER_HELP})")
            opts.add(ch)
    if not patterns:
        if not rest:
            raise ValueError("grep: no pattern given")
        patterns.append(rest.pop(0))
    if rest:
        raise ValueError("grep: only filters the piped output - file arguments are not supported")
    extended = extended or "E" in opts
    parts = [re.escape(x) if "F" in opts else (x if extended else _bre_to_re(x)) for x in patterns]
    pattern = "|".join(f"(?:{x})" for x in parts)
    if "w" in opts:
        pattern = rf"(?<!\w)(?:{pattern})(?!\w)"
    rx = re.compile(pattern, re.I if "i" in opts else 0)
    invert, count, number = "v" in opts, "c" in opts, "n" in opts

    def run(lines):
        n = 0
        for i, line in enumerate(lines, 1):
            if bool(rx.search(line)) != invert:
                n += 1
                if not count:
                    yield f"{i}:{line}" if number else line
        if count:
            yield str(n)
    return run


def _line_count(name, args):
    """head/tail: -n N, -nN or -N. Default 10."""
    n, rest = 10, list(args)
    while rest:
        a = rest.pop(0)
        if a == "-n" and rest:
            a = "-n" + rest.pop(0)
        v = a[2:] if a.startswith("-n") else a[1:] if a.startswith("-") else ""
        if not v.isdigit():
            raise ValueError(f"{name}: only -n N is supported")
        n = int(v)
    return n


def _head(args):
    n = _line_count("head", args)
    return lambda lines: itertools.islice(lines, n)


def _tail(args):
    n = _line_count("tail", args)
    return lambda lines: iter(deque(lines, maxlen=n))


def _wc(args):
    opts = set()
    for a in args:
        if not a.startswith("-") or not a[1:] or not set(a[1:]) <= set("lwc"):
            raise ValueError("wc: only -l -w -c are supported")
        opts |= set(a[1:])

    def run(lines):
        nl = nw = nc = 0
        for line in lines:
            nl, nw, nc = nl + 1, nw + len(line.split()), nc + len(line.encode()) + 1
        vals = [v for k, v in (("l", nl), ("w", nw), ("c", nc)) if not opts or k in opts]
        yield " ".join(f"{v:>7}" for v in vals) if len(vals) > 1 else str(vals[0])
    return run


def _sort(args):
    opts, field, rest = set(), None, list(args)
    while rest:
        a = rest.pop(0)
        if a == "-k" and rest:
            a = "-k" + rest.pop(0)
        m = re.fullmatch(r"-k(\d+)(?:,\d+)?([nrf]*)", a)
        if m:
            field = int(m.group(1))
            opts |= set(m.group(2))
        elif a.startswith("-") and a[1:] and set(a[1:]) <= set("rnuf"):
            opts |= set(a[1:])
        else:
            raise ValueError("sort: supports -r -n -u -f -k N")

    def key(line):
        v = line
        if field:
            cols = line.split()
            v = cols[field - 1] if len(cols) >= field else ""
        if "f" in opts:
            v = v.lower()
        if "n" in opts:
            m = re.match(r"\s*-?\d+(?:\.\d+)?", v)
            return (float(m.group()) if m else 0.0, line)
        return v

    def run(lines):
        seen = set()
        for line in sorted(lines, key=key, reverse="r" in opts):
            if "u" in opts:
                k = key(line)
                if k in seen:
                    continue
                seen.add(k)
            yield line
    return run


def _uniq(args):
    opts = set()
    for a in args:
        if not a.startswith("-") or not a[1:] or not set(a[1:]) <= set("cdui"):
            raise ValueError("uniq: only -c -d -u -i are supported")
        opts |= set(a[1:])

    def run(lines):
        for _k, grp in itertools.groupby(lines, key=str.lower if "i" in opts else None):
            g = list(grp)
            if ("d" in opts and len(g) < 2) or ("u" in opts and len(g) > 1):
                continue
            yield f"{len(g):>7} {g[0]}" if "c" in opts else g[0]
    return run


def _column(args):
    """`column -t`: re-align whitespace-separated columns over the lines that are left. kubectl
    pads a table to its widest row BEFORE grep drops rows, so a filtered table keeps columns
    sized for rows that are gone. Cells must not be empty (custom-columns prints <none>)."""
    if any(a != "-t" for a in args):
        raise ValueError("column: only -t is supported")

    def run(lines):
        rows = [ln.split() for ln in lines]
        widths = {}
        for r in rows:
            for i, cell in enumerate(r):
                widths[i] = max(widths.get(i, 0), len(cell))
        for r in rows:
            yield "   ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip()
    return run


PIPE_FILTERS = {"grep": _grep, "egrep": lambda a: _grep(a, extended=True), "head": _head,
                "tail": _tail, "wc": _wc, "sort": _sort, "uniq": _uniq, "column": _column}


def build_filters(stages):
    """The stages after the first |, as line filters. ValueError names what is not allowed."""
    filters = []
    for st in stages:
        name = st[0]
        if name not in PIPE_FILTERS:
            raise ValueError(f"'{name}' cannot follow a |. Supported after |: {PIPE_FILTER_HELP}")
        try:
            filters.append(PIPE_FILTERS[name](st[1:]))
        except re.error as e:
            raise ValueError(f"{name}: bad pattern: {e}") from e
    return filters


def _exec_pipeline_stream(argv, filters, raw):
    """Like _exec_stream, but stdout goes through the filters line by line. stderr is passed
    straight through. A filter that stops early (head) stops the exec too."""
    from kubernetes.stream import stream as kstream
    api, _batch, _ = k8s()
    pod = runner_pod(api)
    yield f"$ {raw.strip()}\n\n"
    resp = kstream(api.connect_get_namespaced_pod_exec, pod, RUNNER_NS,
                   command=argv, stderr=True, stdout=True, stdin=False, tty=False,
                   _preload_content=False)
    errs, state = [], {"finished": False}

    def stdout_lines():
        buf = ""
        try:
            while resp.is_open():
                resp.update(timeout=1)
                if resp.peek_stderr():
                    errs.append(resp.read_stderr())
                if resp.peek_stdout():
                    buf += resp.read_stdout()
                    *complete, buf = buf.split("\n")
                    yield from complete
            if resp.peek_stdout():
                buf += resp.read_stdout()
            if resp.peek_stderr():
                errs.append(resp.read_stderr())
            yield from (x for x in buf.split("\n") if x)
            state["finished"] = True
        finally:
            resp.close()

    src = stdout_lines()
    lines = src
    for f in filters:
        lines = f(lines)
    emitted = 0
    try:
        for line in lines:
            while errs:
                yield errs.pop(0)
            emitted += 1
            yield line + "\n"
    finally:
        src.close()
    while errs:
        yield errs.pop(0)
    rc = resp.returncode if state["finished"] else 0
    if rc:
        yield f"\n[exit {rc}]\n"
    elif not emitted:
        yield "\n[done] no lines matched\n"
    else:
        yield "\n[done]\n"


@app.post("/api/exec")
def api_exec():
    raw = (request.json or {}).get("cmd", "")
    try:
        stages = split_pipeline(raw)
    except ValueError as e:
        return Response(f"cannot parse command: {e}\n", mimetype="text/plain", status=400)
    # Only the first stage runs in the runner, so only it is subject to the allowlist; the
    # rest are panel-side filters, checked by build_filters().
    argv = expand_alias(stages[0])
    ok, why = allowed(argv)
    if not ok:
        return Response(f"refused: {why}\n", mimetype="text/plain", status=403)
    try:
        filters = build_filters(stages[1:])
    except ValueError as e:
        return Response(f"refused: {e}\n", mimetype="text/plain", status=400)
    try:
        gen = _exec_pipeline_stream(argv, filters, raw) if filters else _exec_stream(argv)
        return Response(stream_with_context(_errors_as_output(gen)), mimetype="text/plain")
    except Exception as e:                                   # noqa: BLE001
        return Response(f"{type(e).__name__}: {e}\n", mimetype="text/plain", status=500)


def _sim_job(scenarios, privileged):
    """Job manifest for the alert-triage image. ttl cleans finished Jobs up by itself."""
    env = [{"name": "SCENARIO", "value": ",".join(scenarios)},
           {"name": "KEEP_ALIVE", "value": "false"}]
    env += [{"name": k, "value": v} for k, v in SIM_DEFAULTS.items()]
    container = {"name": "tester", "image": ALERT_SIM_IMAGE, "imagePullPolicy": "Always",
                 "env": env}
    pod = {"restartPolicy": "Never", "containers": [container]}
    if privileged:
        # Some scenarios need elevation to produce useful telemetry (namespace, chattr,
        # privileged command, host file access). Lab clusters only.
        container["securityContext"] = {"privileged": True}
        pod["hostPID"] = True
        container["volumeMounts"] = [
            {"name": "kubelet", "mountPath": "/var/lib/kubelet", "readOnly": True},
            {"name": "k8setc", "mountPath": "/etc/kubernetes", "readOnly": True}]
        pod["volumes"] = [
            {"name": "kubelet", "hostPath": {"path": "/var/lib/kubelet", "type": "DirectoryOrCreate"}},
            {"name": "k8setc", "hostPath": {"path": "/etc/kubernetes", "type": "DirectoryOrCreate"}}]
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": SIM_JOB, "namespace": SIM_NS,
                         "labels": {"app": SIM_JOB, "purpose": "defender-demo"}},
            "spec": {"backoffLimit": 0, "ttlSecondsAfterFinished": 900,
                     "template": {"metadata": {"labels": {"app": SIM_JOB}}, "spec": pod}}}


def _sim_stream(scenarios, privileged):
    """Delete any previous run, start a new one, stream its logs. This IS the re-run."""
    import time
    core, batch, kclient = k8s()
    ApiException = kclient.exceptions.ApiException

    yield f"$ scenarios: {','.join(scenarios)}   privileged={privileged}   ns={SIM_NS}\n"
    # 1. delete the previous Job (and its pods) if present, then wait for it to go
    try:
        batch.delete_namespaced_job(SIM_JOB, SIM_NS, propagation_policy="Background")
        yield "[re-run] deleting previous job"
        for _ in range(60):
            try:
                batch.read_namespaced_job(SIM_JOB, SIM_NS)
                yield "."
                time.sleep(1)
            except ApiException as e:
                if e.status == 404:
                    break
                raise
        yield " gone\n"
    except ApiException as e:
        if e.status != 404:
            yield f"[warn] delete failed: {e.status} {e.reason}\n"

    # 2. create
    batch.create_namespaced_job(SIM_NS, _sim_job(scenarios, privileged))
    yield "[run] job created, waiting for pod"

    # 3. wait for the pod, then follow its logs
    pod_name = None
    for _ in range(120):
        pods = core.list_namespaced_pod(SIM_NS, label_selector=f"app={SIM_JOB}").items
        running = [p for p in pods if p.status.phase in ("Running", "Succeeded", "Failed")]
        if running:
            pod_name = running[0].metadata.name
            break
        yield "."
        time.sleep(1)
    if not pod_name:
        yield "\n[error] pod never started. Check image pull and quota:\n"
        yield f"  kubectl -n {SIM_NS} describe job/{SIM_JOB}\n"
        return
    yield f" {pod_name}\n\n"

    stream = core.read_namespaced_pod_log(pod_name, SIM_NS, follow=True,
                                          _preload_content=False)
    for chunk in stream.stream():
        yield chunk.decode(errors="replace")
    yield ("\n[done] scenarios finished. Alerts appear in Defender for Cloud / XDR - some in "
           "near real time, some take up to an hour.\n")


@app.get("/api/sim/scenarios")
def api_sim_scenarios():
    return jsonify(groups=SCENARIO_GROUPS, image=ALERT_SIM_IMAGE, namespace=SIM_NS,
                   configured=bool(ALERT_SIM_IMAGE))


@app.post("/api/sim")
def api_sim():
    body = request.json or {}
    scenarios = body.get("scenarios") or ["binary_drift"]
    privileged = bool(body.get("privileged"))
    if not ALERT_SIM_IMAGE:
        return Response("refused: ALERT_SIM_IMAGE is not set. Build and push "
                        "app/mdc-alert-simulation (make app), then redeploy.\n",
                        mimetype="text/plain", status=501)
    if KUBECTL_MODE == "readonly":
        return Response(f"refused: simulations need KUBECTL_MODE=demo (current: {KUBECTL_MODE})\n",
                        mimetype="text/plain", status=403)
    unknown = [x for x in scenarios if x not in SCENARIOS and x != "all"]
    if unknown:
        return Response(f"refused: unknown scenario(s): {', '.join(unknown)}\n",
                        mimetype="text/plain", status=400)
    if privileged and KUBECTL_MODE != "unrestricted":
        return Response("refused: the privileged variant needs KUBECTL_MODE=unrestricted "
                        "(it grants hostPID + privileged + host mounts)\n",
                        mimetype="text/plain", status=403)
    try:
        return Response(stream_with_context(
            _errors_as_output(_sim_stream(scenarios, privileged))), mimetype="text/plain")
    except Exception as e:                                   # noqa: BLE001
        return Response(f"{type(e).__name__}: {e}\n", mimetype="text/plain", status=500)


# ---- verify admission controls ---------------------------------------------------
# One click before a demo: is the cluster actually guarded? Runs in the kubectl runner like the
# console: reads, plus three SERVER-SIDE DRY RUNS that pass through admission and are never
# persisted. No new permissions: the runner already reads the Defender CRDs and admission
# policies, and may create pods in x-mdc-blocked.
MISCONFIG_TEST_IMAGE = "mcr.microsoft.com/azurelinux/base/core:3.0"
# The restricted counterpart, used by the manual button and the third dry run.
RESTRICTED_SECURITY_CONTEXT = {
    "privileged": False, "runAsNonRoot": True, "runAsUser": 1000,
    "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}


def _exec_capture(argv):
    """Exec argv in the kubectl-runner pod and return (exit code, combined output)."""
    from kubernetes.stream import stream as kstream
    api, _batch, _ = k8s()
    resp = kstream(api.connect_get_namespaced_pod_exec, runner_pod(api), RUNNER_NS,
                   command=argv, stderr=True, stdout=True, stdin=False, tty=False,
                   _preload_content=False)
    out = []
    while resp.is_open():
        resp.update(timeout=1)
        if resp.peek_stdout():
            out.append(resp.read_stdout())
        if resp.peek_stderr():
            out.append(resp.read_stderr())
    resp.close()
    return resp.returncode or 0, "".join(out).strip()


def _rows(rc, out):
    """Non-empty output lines of a --no-headers listing; none when kubectl failed or found nothing."""
    if rc:
        return []
    return [line for line in out.splitlines() if line.strip() and not line.startswith("No resources")]


def _verify_admission_stream():
    acr = ACR_LOGIN_SERVER or "<acr>.azurecr.io"
    tally = {"ok": 0, "bad": 0, "warn": 0}

    def report(state, title, detail="", hint=""):
        tally[state] += 1
        text = f"{ {'ok': '✔', 'bad': '✘', 'warn': '!'}[state] } {title}\n"
        text += "".join(f"    {d}\n" for d in detail.splitlines()[:8] if d.strip())
        # Trailing blank line: each check reads as its own block in the console.
        return text + (f"    → {hint}\n" if hint else "") + "\n"

    yield "verify admission controls · reads + server-side dry runs, nothing is created\n\n"

    # 1. the sensor's admission controller
    rc, out = _exec_capture(["kubectl", "get", "deploy", "defender-admission-controller", "-n",
                             DEFENDER_NS, "-o", "jsonpath={.status.readyReplicas}/{.spec.replicas}"])
    ready, _, want = out.partition("/")
    if rc == 0 and ready and ready == want:
        yield report("ok", f"admission controller ready in {DEFENDER_NS} ({out})")
    else:
        yield report("bad", f"admission controller not ready in {DEFENDER_NS}", out,
                     "Helm sensor: make sensor-helm; add-on: check securityProfile.defender")

    # 2. the image gate webhook
    rc, out = _exec_capture(["kubectl", "get", "validatingwebhookconfigurations", "-o", "name"])
    hooks = [h for h in _rows(rc, out) if "defender" in h]
    yield (report("ok", "image gate webhook registered", "\n".join(hooks)) if hooks else
           report("bad", "no Defender admission webhook registered", out))

    # 2b. Trusted Access: Defender pushes its rules into the cluster through an AKS Trusted Access
    # binding. Each binding materialises as a ClusterRole aks:trustedaccessrole:<binding>:<role>.
    rc, out = _exec_capture(["kubectl", "get", "clusterroles", "-o", "name"])
    ta = [r.split("/", 1)[-1] for r in _rows(rc, out) if "aks:trustedaccessrole:" in r]
    if any(r.endswith(":microsoft-defender-policy-operator") for r in ta):
        yield report("ok", "Trusted Access: microsoft-defender-policy-operator bound "
                     "(Defender can push gating + misconfiguration rules)")
    else:
        yield report("bad", "Trusted Access: no microsoft-defender-policy-operator binding",
                     "\n".join(ta) or "no aks:trustedaccessrole:* ClusterRoles at all",
                     "rules cannot reach the cluster; az aks trustedaccess rolebinding create "
                     "--roles Microsoft.Security/pricings/microsoft-defender-policy-operator "
                     "(make verify-gating prints the full command)")
    if not any(r.endswith(":mdc-response-operator") for r in ta):
        yield report("warn", "Trusted Access: no mdc-response-operator binding",
                     hint="Defender XDR isolate / restrict pod cannot run on this cluster")

    # 3. gated-deployment rules synced from Defender for Cloud
    rc, out = _exec_capture(["kubectl", "get", "securityartifactpolicies.defender.microsoft.com",
                             "-A", "--no-headers"])
    rules = _rows(rc, out)
    yield (report("ok", f"gated-deployment rules synced: {len(rules)} SecurityArtifactPolicy",
                  "\n".join(rules)) if rules else
           report("bad", "no gated-deployment rules on the cluster", out,
                  "create a rule in Environment settings > Containers > gated deployment; "
                  "a freshly installed sensor can take several minutes to receive it"))

    # 4. misconfiguration policies (ValidatingAdmissionPolicy bindings) and their action
    rc, out = _exec_capture(["kubectl", "get", "validatingadmissionpolicybindings", "--no-headers",
                             "-o", "custom-columns=NAME:.metadata.name,ACTIONS:.spec.validationActions"])
    # Only Defender's: AKS ships its own aks-managed-* bindings (wireserver protection) that
    # say nothing about pod misconfiguration.
    bindings = [b for b in _rows(rc, out) if not b.startswith("aks-managed-")]
    deny = [b for b in bindings if "Deny" in b]
    if deny:
        yield report("ok", f"misconfiguration policies: {len(bindings)} binding(s), {len(deny)} deny",
                     "\n".join(deny))
    elif bindings:
        yield report("warn", f"misconfiguration policies: {len(bindings)} binding(s), all audit-only",
                     "\n".join(bindings), "nothing is refused; switch the rule to deny in Defender")
    else:
        yield report("bad", "no Defender misconfiguration policies (ValidatingAdmissionPolicy bindings)", out,
                     "Helm sensor with defender-admission-controller.enableMisconfigurationPolicies=true")

    # 4b. Azure Policy add-on (Gatekeeper). Not part of the gate, but Defender still needs it for
    # the recommendations on RUNNING containers (vulnerable images in use). Its warnings and
    # denials show in violet in this console, Defender's in red.
    rc, out = _exec_capture(["kubectl", "get", "constraints", "--no-headers", "-o",
                             "custom-columns=NAME:.metadata.name,ACTION:.spec.enforcementAction"])
    constraints = _rows(rc, out)
    if constraints:
        actions = {}
        for c in constraints:
            parts = c.split()
            action = parts[1] if len(parts) > 1 else "?"
            actions[action] = actions.get(action, 0) + 1
        mix = ", ".join(f"{n} {a}" for a, n in sorted(actions.items()))
        yield report("ok", f"Azure Policy add-on (Gatekeeper): {len(constraints)} constraint(s) · {mix}",
                     "\n".join(constraints))
    else:
        yield report("warn", "Azure Policy add-on (Gatekeeper) not found", out,
                     "Defender needs it for recommendations on running containers with CVEs; "
                     "az aks enable-addons --addons azure-policy")

    if KUBECTL_MODE == "readonly":
        yield "! dry runs skipped: they need KUBECTL_MODE=demo (current: readonly)\n\n"
    else:
        # 5. the image gate refuses the vulnerable app in the gated namespace
        who = "pod verify-gate (aks-webapp:latest) in x-mdc-blocked"
        rc, out = _exec_capture(["kubectl", "run", "verify-gate", "-n", "x-mdc-blocked",
                                 "--restart=Never", "--dry-run=server",
                                 f"--image={acr}/aks-webapp:latest"])
        low = out.lower()
        if rc and "defender-admission-controller" in low:
            yield report("ok", f"image gate DENIES {who}", out)
        elif rc and "gatekeeper" in low:
            yield report("warn", f"Azure Policy (Gatekeeper) DENIES {who}, not the Defender "
                         "image gate", out)
        elif rc and "denied" in low:
            yield report("ok", f"image gate DENIES {who}", out)
        elif rc == 0:
            yield report("bad", f"image gate ADMITTED {who} - the gate fails open",
                         out, "check the admission controller logs for AUTH_DENIED / REFERRER_STORE_FAILURE")
        else:
            yield report("warn", f"dry run of {who} failed without an admission verdict", out)

        # 6. the misconfiguration policy refuses a privileged root pod. A plain MCR base image,
        # so the verdict is about the pod spec; VAPs run before the image webhook.
        overrides = json.dumps({"spec": {"containers": [{
            "name": "verify-misconfig", "image": MISCONFIG_TEST_IMAGE, "command": ["sleep", "1"],
            "securityContext": {"privileged": True, "runAsUser": 0,
                                "allowPrivilegeEscalation": True}}]}})
        who = "privileged root pod verify-misconfig (azurelinux base) in x-mdc-blocked"
        rc, out = _exec_capture(["kubectl", "run", "verify-misconfig", "-n", "x-mdc-blocked",
                                 "--restart=Never", "--dry-run=server",
                                 f"--image={MISCONFIG_TEST_IMAGE}", f"--overrides={overrides}"])
        low = out.lower()
        if rc and "validatingadmissionpolic" in low:
            yield report("ok", f"misconfiguration policy DENIES {who}", out)
        elif rc and "gatekeeper" in low:
            yield report("warn", f"Azure Policy (Gatekeeper) DENIES {who}, not a Defender "
                         "misconfiguration policy", out)
        elif rc and "denied" in low:
            yield report("warn", f"image gate DENIES {who}, not a misconfiguration policy", out)
        elif rc == 0:
            yield report("bad", f"misconfiguration policy ADMITTED {who}", out,
                         "misconfiguration enforcement is off or audit-only")
        else:
            yield report("warn", f"dry run of {who} failed without an admission verdict", out)

        # 7. ...and still admits a restricted pod with a clean, scanned image: the gates refuse
        # what they should, not everything in the namespace.
        alpine = f"{acr}/misconfig-alpine:latest"
        overrides = json.dumps({"spec": {"containers": [{
            "name": "verify-restricted", "image": alpine,
            "securityContext": RESTRICTED_SECURITY_CONTEXT}]}})
        who = "restricted pod verify-restricted (misconfig-alpine:latest) in x-mdc-blocked"
        rc, out = _exec_capture(["kubectl", "run", "verify-restricted", "-n", "x-mdc-blocked",
                                 "--restart=Never", "--dry-run=server",
                                 f"--image={alpine}", f"--overrides={overrides}"])
        low = out.lower()
        if rc == 0:
            yield report("ok", f"both gates ADMIT {who}", out)
        elif "validatingadmissionpolic" in low:
            yield report("bad", f"misconfiguration policy DENIES {who}", out,
                         "a policy denies more than privileged/root; check its binding and parameters")
        elif "gatekeeper" in low:
            yield report("warn", f"Azure Policy (Gatekeeper) DENIES {who}", out,
                         "an Azure Policy assignment in deny mode objects to this spec")
        elif "denied" in low:
            yield report("warn", f"image gate DENIES {who}", out,
                         "misconfig-alpine:latest missing, not scanned yet or has new CVEs; "
                         "run the demo · misconfiguration workflow")
        else:
            yield report("warn", f"dry run of {who} failed without an admission verdict", out)

    verdict = "GUARDED" if not tally["bad"] and not tally["warn"] else (
        "NOT GUARDED" if tally["bad"] else "PARTLY GUARDED")
    yield (f"{verdict}: {tally['ok']} ok, {tally['warn']} warning(s), {tally['bad']} failed\n")


@app.post("/api/verify-admission")
def api_verify_admission():
    try:
        return Response(stream_with_context(_errors_as_output(_verify_admission_stream())),
                        mimetype="text/plain")
    except Exception as e:                                   # noqa: BLE001
        return Response(f"{type(e).__name__}: {e}\n", mimetype="text/plain", status=500)


@app.post("/api/chat")
def api_chat():
    """Mode A: direct model inference on the Foundry deployment. Defender for AI Services
    covers this: jailbreak / Prompt Shields, credential theft, wallet attacks, and the
    prompt itself as alert evidence.
    Mode B: a PUBLISHED Foundry agent - agent-level detection needs Microsoft Agent 365."""
    if not FOUNDRY_ENDPOINT:
        return jsonify(error="Foundry is not deployed (deployFoundry=false). "
                             "Redeploy with deployFoundry=true to enable the chat."), 501
    body = request.json or {}
    prompt = (body.get("prompt") or "").strip()
    mode = body.get("mode", "model")
    if not prompt:
        return jsonify(error="empty prompt"), 400
    user, src_ip = _end_user()

    if mode == "agent":
        return jsonify(mode="agent", user=user, endpoint=FOUNDRY_ENDPOINT,
                       note="Mode B calls a PUBLISHED Foundry agent endpoint. Agent-level "
                            "threat detection requires a Microsoft Agent 365 license and only "
                            "covers published agents. Publish one with "
                            "infra/postdeploy/foundry-agent.sh, then point this at its endpoint."), 501

    try:
        from azure.identity import DefaultAzureCredential, get_bearer_token_provider
        from openai import AzureOpenAI
        provider = get_bearer_token_provider(
            DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default")
        client = AzureOpenAI(azure_endpoint=FOUNDRY_ENDPOINT,
                             azure_ad_token_provider=provider,
                             api_version=os.environ.get("AI_API_VERSION", "2024-10-21"))
        # user_security_context lets Defender for AI attribute the alert to the real end user
        # instead of to this app's managed identity.
        usc = {"end_user_id": user}
        if src_ip:
            usc["source_ip"] = src_ip
        reply = client.chat.completions.create(
            model=AI_MODEL_NAME,
            messages=[{"role": "system", "content": "You are the demo assistant for a "
                                                    "Kubernetes security lab."},
                      {"role": "user", "content": prompt}],
            user=user,
            extra_body={"user_security_context": usc},
        )
        return jsonify(mode="model", user=user, model=AI_MODEL_NAME,
                       reply=reply.choices[0].message.content)
    except Exception as e:                                   # noqa: BLE001
        # A content-filter / Prompt Shields block arrives as an API error. That IS the demo:
        # the request was refused AND Defender for AI raises the alert.
        return jsonify(mode="model", user=user, model=AI_MODEL_NAME,
                       blocked=True, detail=f"{type(e).__name__}: {e}",
                       note="If this was a jailbreak attempt, Prompt Shields blocked it and "
                            "Defender for AI Services should raise an alert within minutes."), 200


# ---- heartbeat: the isolation drill ------------------------------------------
# The x-mdc-allowed copy of this app calls the control panel's public /healthz every 15s and
# logs the result to stdout. Isolate the pod from Defender XDR and the network policy cuts
# its egress: the next beat logs ERROR, which `kubectl logs` shows in red in the console.
# Off unless HEARTBEAT_URL is set, so the control panel (same image) never beats itself.
# Any HTTP answer counts as reachable - a 401 still proves the network path is open.
HEARTBEAT_URL = os.environ.get("HEARTBEAT_URL", "")
HEARTBEAT_SECONDS = int(os.environ.get("HEARTBEAT_SECONDS", "15"))
_connections["heartbeat"].update(configured=bool(HEARTBEAT_URL),
                                 status=("pending" if HEARTBEAT_URL else "disabled"),
                                 target=HEARTBEAT_URL)


def _heartbeat_loop():
    import time
    import requests
    pod = os.environ.get("HOSTNAME", "?")
    print(f"[heartbeat] started on {pod}: GET {HEARTBEAT_URL} every {HEARTBEAT_SECONDS}s",
          flush=True)
    failed = 0
    while True:
        t0 = time.monotonic()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            r = requests.get(HEARTBEAT_URL, timeout=(5, 5))
            ms = int((time.monotonic() - t0) * 1000)
            line = f"{stamp} [heartbeat] OK HTTP {r.status_code} in {ms}ms"
            if failed:
                line += f" - recovered after {failed} failed beat(s)"
            failed = 0
            _connections["heartbeat"].update(status="ok", last_checked=stamp,
                                              detail=f"HTTP {r.status_code} in {ms}ms", error="")
        except Exception as e:                               # noqa: BLE001
            failed += 1
            line = (f"{stamp} [heartbeat] ERROR {type(e).__name__}: {str(e)[:200]} "
                    f"(failed {failed}x in a row - egress blocked, pod isolated?)")
            _connections["heartbeat"].update(status="error", last_checked=stamp,
                                              detail="", error=f"{type(e).__name__}: {str(e)[:160]}")
        print(line, flush=True)
        time.sleep(max(0.0, HEARTBEAT_SECONDS - (time.monotonic() - t0)))


def _blob_probe_loop():
    """Fetch and expose only the explicitly synthetic demo records through the AKS page."""
    import time
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobClient

    credential = DefaultAzureCredential()
    blob = BlobClient(account_url=STORAGE_ACCOUNT_URL, container_name=STORAGE_CONTAINER,
                      blob_name=STORAGE_BLOB, credential=credential)
    print(f"[blob] started: GET {STORAGE_ACCOUNT_URL}/{STORAGE_CONTAINER}/{STORAGE_BLOB} "
          f"every {STORAGE_POLL_SECONDS}s using workload identity", flush=True)
    while True:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            raw = blob.download_blob().readall()
            doc = json.loads(raw.decode("utf-8"))
            records = doc.get("records", [])
            if not isinstance(records, list):
                raise ValueError("records must be a JSON array")
            _connections["blob"].update(
                status="ok", last_checked=stamp, error="", bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
                classification=str(doc.get("classification", "FAKE SENSITIVE DATA")),
                records=records,
            )
            print(f"{stamp} [blob] OK retrieved {len(records)} fake sensitive record(s) "
                  f"({len(raw)} bytes)", flush=True)
        except Exception as e:                               # noqa: BLE001
            _connections["blob"].update(status="error", last_checked=stamp, records=[],
                                         error=f"{type(e).__name__}: {str(e)[:200]}")
            print(f"{stamp} [blob] ERROR {type(e).__name__}: {str(e)[:200]}", flush=True)
        time.sleep(max(5, STORAGE_POLL_SECONDS))


if __name__ == "__main__":
    import threading
    if HEARTBEAT_URL:
        threading.Thread(target=_heartbeat_loop, name="heartbeat", daemon=True).start()
    if STORAGE_ACCOUNT_URL:
        threading.Thread(target=_blob_probe_loop, name="blob-probe", daemon=True).start()
    app.run(host="0.0.0.0", port=8080)
