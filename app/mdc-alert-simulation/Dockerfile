FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV SCENARIO=list
ENV KEEP_ALIVE=false
ENV CANARY_DOMAIN=canary.invalid
ENV SUSPICIOUS_DNS=mdc-eicar.alerts.security.azure.com
ENV SUSPICIOUS_IP=abcdefghijklmnop.onion.to
ENV MINING_POOL_DOMAIN=poolmining.org
ENV METADATA_URL=http://169.254.169.254/metadata/instance?api-version=2021-02-01

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      attr \
      bind9-dnsutils \
      ca-certificates \
      cron \
      curl \
      iproute2 \
      netcat-openbsd \
      nmap \
      openssh-server \
      php-cli \
      procps \
      socat \
      tini \
      util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

COPY mdc-alert-runner.sh /usr/local/bin/mdc-alert-runner
# Strip any CRLF line endings (e.g. when built from a Windows checkout) so the
# shebang resolves to /bin/sh and not /bin/sh\r, then make it executable.
RUN sed -i 's/\r$//' /usr/local/bin/mdc-alert-runner \
    && chmod +x /usr/local/bin/mdc-alert-runner

# Serverless run-to-completion: the script runs the scenarios and exits
# (KEEP_ALIVE defaults to false). tini forwards SIGTERM from the platform
# (ACI/Container Apps Jobs/Fargate/Cloud Run Jobs) cleanly and reaps the
# background processes some scenarios spawn (e.g. sshd, miner_process).
# -s registers tini as a child subreaper so reaping still works when it is not
# PID 1 (e.g. a Kubernetes pod with a shared/host PID namespace).
ENTRYPOINT ["/usr/bin/tini", "-s", "--", "/usr/local/bin/mdc-alert-runner"]
