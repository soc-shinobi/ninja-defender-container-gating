# Microsoft Defender for Containers Alert Triage Tester

This image runs benign Linux/container behaviors that can help validate Microsoft Defender for Containers alert triage. Use it only in a dedicated non-production cluster.

The image intentionally does not include malware, real credential dumping, real campaign emulation, or connections to malicious infrastructure. Point domain/IP tests at approved canary infrastructure with environment variables.

## Build

```bash
docker build -t mdc-alert-triage-tester:local .
```

## Run locally

```bash
docker run --rm mdc-alert-triage-tester:local
docker run --rm -e SCENARIO=network_scan mdc-alert-triage-tester:local
docker run --rm -e SCENARIO=base64_exec,secret_recon mdc-alert-triage-tester:local
docker run --rm -e SCENARIO=all mdc-alert-triage-tester:local
```

## Push

```bash
docker tag mdc-alert-triage-tester:local <registry>/mdc-alert-triage-tester:latest
docker push <registry>/mdc-alert-triage-tester:latest
```

## Deploy as Kubernetes job

```bash
kubectl create ns mdc-alert-test
kubectl run mdc-alert-test \
  -n mdc-alert-test \
  --image=<registry>/mdc-alert-triage-tester:latest \
  --restart=Never \
  --env=SCENARIO=all
```

Show logs:

```bash
kubectl logs -n mdc-alert-test pod/mdc-alert-test
```

Cleanup:

```bash
kubectl delete ns mdc-alert-test
```

## Privileged deployment variant

Some scenarios need elevated container permissions to produce useful telemetry, for example namespace, chattr, privileged command, or host-related file access. Use the provided `k8s-job-privileged.yaml` only in a lab cluster.

```bash
kubectl create ns mdc-alert-test
kubectl apply -n mdc-alert-test -f k8s-job-privileged.yaml
kubectl logs -n mdc-alert-test job/mdc-alert-triage-tester
```

Edit the image name in the manifest before applying.

## Scenario selection

Set `SCENARIO` to one scenario, comma-separated scenarios, `all`, or `list`.

Available scenarios:

```text
base64_exec
bash_profile_access
bash_history_access
cron_ops
network_scan
netcat_activity
proxy_tool
metadata_access
suspicious_dns
suspicious_ip
oast_domain
namespace_create
chattr_change
timestamp_modify
log_tamper
history_impair
sensitive_file_access
serviceaccount_token_access
secret_recon
download_chmod_exec
binary_drift
miner_process
miner_process_kill
mining_pool_access
php_execution
reverse_shell_pattern
path_traversal
k8s_api_request
kubelet_kubeconfig_access
sshd_container
privileged_command
account_sudo
malware_test_placeholder
```

Configurable values:

```text
CANARY_DOMAIN
SUSPICIOUS_DNS
SUSPICIOUS_IP
MINING_POOL_DOMAIN
METADATA_URL
KEEP_ALIVE
```
