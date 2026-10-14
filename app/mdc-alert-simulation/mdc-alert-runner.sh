#!/bin/sh
set -eu

SCENARIO="${SCENARIO:-list}"
KEEP_ALIVE="${KEEP_ALIVE:-false}"
CANARY_DOMAIN="${CANARY_DOMAIN:-canary.invalid}"
SUSPICIOUS_DNS="${SUSPICIOUS_DNS:-suspicious-mdc-test.example.com}"
SUSPICIOUS_IP="${SUSPICIOUS_IP:-203.0.113.10}"
MINING_POOL_DOMAIN="${MINING_POOL_DOMAIN:-pool.minexmr.example.com}"
METADATA_URL="${METADATA_URL:-http://169.254.169.254/metadata/instance?api-version=2021-02-01}"

log() {
  printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

run() {
  log "$1"
  shift
  "$@" || true
}

shrun() {
  log "$1"
  shift
  sh -lc "$*" || true
}

list_scenarios() {
  cat <<'EOF'
Set SCENARIO to one value, comma-separated values, or all.

Available scenarios:
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

Examples:
  docker run --rm mdc-alert-triage-tester
  docker run --rm -e SCENARIO=network_scan mdc-alert-triage-tester
  docker run --rm -e SCENARIO=base64_exec,secret_recon mdc-alert-triage-tester
  docker run --rm -e SCENARIO=all mdc-alert-triage-tester
EOF
}

scenario_base64_exec() {
  shrun "Base64 encoded shell script execution" \
    'echo "ZWNobyBtZGMtYmFzZTY0LXRlc3QK" | base64 -d | sh'
}

scenario_bash_profile_access() {
  shrun "Unusual access to Bash profile file" \
    'touch /root/.bashrc /root/.bash_profile; cat /root/.bashrc >/dev/null; echo "# mdc-test $(date -u +%s)" >> /root/.bash_profile'
}

scenario_bash_history_access() {
  shrun "Unusual access to bash history file" \
    'touch /root/.bash_history; cat /root/.bash_history >/dev/null; echo "mdc-history-test" >> /root/.bash_history'
}

scenario_cron_ops() {
  shrun "Suspicious cron operations" \
    'echo "* * * * * echo mdc-cron-test >/tmp/mdc-cron.log" | crontab -; crontab -l; crontab -r'
}

scenario_network_scan() {
  shrun "Network scanning tool detected" \
    'nmap -sT -Pn 127.0.0.1 -p 1-100'
}

scenario_netcat_activity() {
  shrun "Suspicious netcat activity" \
    'nc -zv 127.0.0.1 80'
}

scenario_proxy_tool() {
  shrun "Backdoor/proxy utility style command lines" \
    'socat -V; nc -h'
}

scenario_metadata_access() {
  shrun "Cloud metadata service access" \
    "curl -m 2 -H 'Metadata:true' '$METADATA_URL'"
}

scenario_suspicious_dns() {
  shrun "Suspicious DNS in command line" \
    "nslookup '$SUSPICIOUS_DNS'"
}

scenario_suspicious_ip() {
  shrun "Suspicious IP in command line" \
    "curl -m 2 'http://$SUSPICIOUS_IP'"
}

scenario_oast_domain() {
  shrun "OAST/canary domain usage" \
    "nslookup '$CANARY_DOMAIN'"
}

scenario_namespace_create() {
  shrun "Attempt to create Linux namespace from container" \
    'unshare --fork --pid sh -c "echo mdc-namespace-test"'
}

scenario_chattr_change() {
  shrun "Suspicious file attribute change using chattr" \
    'touch /tmp/mdc-chattr-test; chattr +i /tmp/mdc-chattr-test; chattr -i /tmp/mdc-chattr-test; rm -f /tmp/mdc-chattr-test'
}

scenario_timestamp_modify() {
  shrun "Suspicious file timestamp modification" \
    'touch /tmp/mdc-time-test; touch -t 200101010101 /tmp/mdc-time-test; stat /tmp/mdc-time-test'
}

scenario_log_tamper() {
  shrun "Possible log tampering activity" \
    'echo test >/tmp/mdc-test.log; truncate -s 0 /tmp/mdc-test.log; mv /tmp/mdc-test.log /tmp/mdc-test.log.old'
}

scenario_history_impair() {
  shrun "Possible impairing of command history logging" \
    'export HISTFILE=/dev/null; unset HISTFILE; history -c 2>/dev/null || true'
}

scenario_sensitive_file_access() {
  shrun "Sensitive files access" \
    'stat /etc/shadow /etc/passwd /proc/self/environ >/dev/null 2>&1'
}

scenario_serviceaccount_token_access() {
  shrun "Workload identity or service account token access" \
    'stat /var/run/secrets/kubernetes.io/serviceaccount/token; head -c 8 /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null'
}

scenario_secret_recon() {
  shrun "Possible secret reconnaissance" \
    'mkdir -p /tmp/mdc-secrets; touch /tmp/mdc-secrets/password.txt /tmp/mdc-secrets/token.env /tmp/mdc-secrets/client_secret.json; find /tmp/mdc-secrets -iname "*password*" -o -iname "*token*" -o -iname "*secret*"'
}

scenario_download_chmod_exec() {
  shrun "Downloaded binary/script granted execute permission from suspicious folder" \
    'printf "#!/bin/sh\necho mdc-download-exec-test\n" >/tmp/mdc-downloaded.sh; chmod +x /tmp/mdc-downloaded.sh; /tmp/mdc-downloaded.sh'
}

scenario_binary_drift() {
  shrun "Binary drift execution" \
    'cp /bin/echo /tmp/mdc-drift-bin; chmod +x /tmp/mdc-drift-bin; /tmp/mdc-drift-bin mdc-binary-drift-test'
}

scenario_miner_process() {
  shrun "Crypto-miner-like process name, benign" \
    'cp /bin/sleep /tmp/xmrig; /tmp/xmrig 5 & pid=$!; sleep 1; ps -ef | grep xmrig | grep -v grep; kill "$pid"'
}

scenario_miner_process_kill() {
  shrun "Kubernetes crypto-miner process kill style behavior, benign" \
    'cp /bin/sleep /tmp/kdevtmpfsi; /tmp/kdevtmpfsi 60 & pid=$!; sleep 1; kill -9 "$pid"'
}

scenario_mining_pool_access() {
  shrun "Mining pool DNS access pattern" \
    "nslookup '$MINING_POOL_DOMAIN'"
}

scenario_php_execution() {
  shrun "Suspicious PHP execution" \
    'php -r "system(\"echo mdc-php-test\");"'
}

scenario_reverse_shell_pattern() {
  shrun "Reverse shell command pattern without outbound connection" \
    'echo "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1" >/tmp/mdc-reverse-shell-pattern.txt; cat /tmp/mdc-reverse-shell-pattern.txt'
}

scenario_path_traversal() {
  shrun "Path traversal request pattern against localhost" \
    'curl -m 2 "http://127.0.0.1/../../../../etc/passwd"'
}

scenario_k8s_api_request() {
  shrun "Suspicious Kubernetes API request pattern using mounted service account token" \
    'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); curl -k -m 3 -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces'
}

scenario_kubelet_kubeconfig_access() {
  shrun "Kubelet kubeconfig access pattern" \
    'stat /var/lib/kubelet/kubeconfig /etc/kubernetes/kubelet.conf 2>/dev/null'
}

scenario_sshd_container() {
  shrun "SSH server running inside a container" \
    'ssh-keygen -A; /usr/sbin/sshd; sleep 3; pgrep -a sshd'
}

scenario_privileged_command() {
  shrun "Command inside container with high privileges" \
    'id; capsh --print 2>/dev/null || true; mount | head'
}

scenario_account_sudo() {
  shrun "Account added to sudo group, if container has permissions" \
    'useradd mdc-test-user 2>/dev/null || true; groupadd sudo 2>/dev/null || true; usermod -aG sudo mdc-test-user 2>/dev/null || true; id mdc-test-user 2>/dev/null || true; gpasswd -d mdc-test-user sudo 2>/dev/null || true; userdel mdc-test-user 2>/dev/null || true'
}

scenario_malware_test_placeholder() {
  log "Malware execution/blocking placeholder"
  cat <<'EOF'
This image does not embed or download malware.
For "Kubernetes Malware execution detected/blocked", enable Defender runtime anti-malware and use your organization's Microsoft-approved EICAR/test-file validation path or Defender sample alert.
EOF
}

run_one() {
  case "$1" in
    base64_exec) scenario_base64_exec ;;
    bash_profile_access) scenario_bash_profile_access ;;
    bash_history_access) scenario_bash_history_access ;;
    cron_ops) scenario_cron_ops ;;
    network_scan) scenario_network_scan ;;
    netcat_activity) scenario_netcat_activity ;;
    proxy_tool) scenario_proxy_tool ;;
    metadata_access) scenario_metadata_access ;;
    suspicious_dns) scenario_suspicious_dns ;;
    suspicious_ip) scenario_suspicious_ip ;;
    oast_domain) scenario_oast_domain ;;
    namespace_create) scenario_namespace_create ;;
    chattr_change) scenario_chattr_change ;;
    timestamp_modify) scenario_timestamp_modify ;;
    log_tamper) scenario_log_tamper ;;
    history_impair) scenario_history_impair ;;
    sensitive_file_access) scenario_sensitive_file_access ;;
    serviceaccount_token_access) scenario_serviceaccount_token_access ;;
    secret_recon) scenario_secret_recon ;;
    download_chmod_exec) scenario_download_chmod_exec ;;
    binary_drift) scenario_binary_drift ;;
    miner_process) scenario_miner_process ;;
    miner_process_kill) scenario_miner_process_kill ;;
    mining_pool_access) scenario_mining_pool_access ;;
    php_execution) scenario_php_execution ;;
    reverse_shell_pattern) scenario_reverse_shell_pattern ;;
    path_traversal) scenario_path_traversal ;;
    k8s_api_request) scenario_k8s_api_request ;;
    kubelet_kubeconfig_access) scenario_kubelet_kubeconfig_access ;;
    sshd_container) scenario_sshd_container ;;
    privileged_command) scenario_privileged_command ;;
    account_sudo) scenario_account_sudo ;;
    malware_test_placeholder) scenario_malware_test_placeholder ;;
    list) list_scenarios ;;
    *)
      log "Unknown scenario: $1"
      list_scenarios
      return 1
      ;;
  esac
}

run_all() {
  for scenario in \
    base64_exec \
    bash_profile_access \
    bash_history_access \
    cron_ops \
    network_scan \
    netcat_activity \
    proxy_tool \
    metadata_access \
    suspicious_dns \
    suspicious_ip \
    oast_domain \
    namespace_create \
    chattr_change \
    timestamp_modify \
    log_tamper \
    history_impair \
    sensitive_file_access \
    serviceaccount_token_access \
    secret_recon \
    download_chmod_exec \
    binary_drift \
    miner_process \
    miner_process_kill \
    mining_pool_access \
    php_execution \
    reverse_shell_pattern \
    path_traversal \
    k8s_api_request \
    kubelet_kubeconfig_access \
    sshd_container \
    privileged_command \
    account_sudo \
    malware_test_placeholder
  do
    run_one "$scenario" || true
  done
}

if [ "$SCENARIO" = "all" ]; then
  run_all
else
  old_ifs="$IFS"
  IFS=","
  for scenario in $SCENARIO; do
    IFS="$old_ifs"
    run_one "$(printf '%s' "$scenario" | tr -d ' ')"
    IFS=","
  done
  IFS="$old_ifs"
fi

if [ "$KEEP_ALIVE" = "true" ]; then
  log "KEEP_ALIVE=true, sleeping"
  sleep infinity
fi
