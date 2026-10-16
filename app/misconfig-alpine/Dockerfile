# Misconfiguration demo image: plain Alpine that only sleeps. It is pushed to ACR and scanned
# by Defender so the x-mdc-blocked image gate (CVEs + "unscanned: deny") lets it through and
# the misconfiguration policy is the only thing that can refuse the pod.
# apk upgrade pulls the latest package fixes so the scan comes back clean.
FROM alpine:3.22
RUN apk upgrade --no-cache
CMD ["sleep", "infinity"]
