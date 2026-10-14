# DELIBERATELY VULNERABLE for the demo:
# - old base image with known CVEs (registry + gated-deployment beat)
# - runs as root (IaC-misconfiguration + VAP misconfiguration beat)
# - no healthcheck, no pinned digest
# - dormant vulnerable content that the app never touches (see below)
# Fix ONCE here at the source in Act 7 (pin a slim current base, add USER).
FROM python:3.9-slim-bullseye

WORKDIR /app
# curl for the panel's crypto-mining drill (curl to a mining pool from this pod).
# Bullseye is EOL: deb.debian.org still lists bullseye-security packages but serves 404s,
# so point apt at archive.debian.org, where both main and security are complete.
RUN printf '%s\n' \
      'deb http://archive.debian.org/debian bullseye main' \
      'deb http://archive.debian.org/debian-security bullseye-security main' \
      > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# ---------------------------------------------------------------------------
# DEAD WEIGHT, ON PURPOSE. Log4j 2.14.1 is the canonical CVE-2021-44228 artifact
# and this image has no Java runtime, so it can never execute: it is inert
# content, not an exploitable path. That is exactly the beat - the scanner
# reports a CRITICAL in an internet-facing workload, the room says "but we do
# not even run Java", and the gate denies the image anyway. Vulnerability
# management judges what you ship, not what you intended to use.
# Remove this line in Act 7 together with the base-image bump.
ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar \
    /opt/vendor/log4j-core-2.14.1.jar

# runs as root on purpose
EXPOSE 8080
CMD ["python", "app.py"]
