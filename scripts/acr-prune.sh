#!/usr/bin/env bash
# Prune the lab registry: per repository keep the newest KEEP tagged image versions, plus
# everything still in use, and delete the rest.
#
#   bash scripts/acr-prune.sh            # dry run: prints what would be deleted
#   APPLY=true bash scripts/acr-prune.sh # deletes
#
# Never deleted:
#   - the newest KEEP tagged manifests of each repository (by push time)
#   - any image referenced in app/k8s (Flux deploys those), by tag or digest
#   - the images the Container Apps in RESOURCE_GROUP run right now
#   - anything tagged "latest" (manual pods and the panel's restricted pod use it)
#   - untagged manifests WITHOUT a subject (e.g. the platform manifests inside an image index)
# Untagged manifests WITH a subject are artifacts attached to an image (Defender security
# findings, signatures). They are deleted only once the image they point at is gone.
#
# ACR Basic has no retention policy (that is a Premium feature), hence this script.
set -euo pipefail

: "${ACR_NAME:?set ACR_NAME}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"
KEEP="${KEEP:-3}"
APPLY="${APPLY:-false}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

mode="DRY RUN"; [[ "$APPLY" == true ]] && mode="APPLY"
echo ">> acr-prune $ACR_NAME · keep newest $KEEP tagged per repository · $mode"

# ---- in use ----------------------------------------------------------------
: > "$TMP/inuse"
# Flux manifests: <anything>/<repo>:<tag> or <repo>@sha256:<digest>
grep -rhoE 'image:[[:space:]]*[^[:space:]]+' "$ROOT/app/k8s" \
  | sed -E 's/^image:[[:space:]]*//; s#^[^/]+/##' >> "$TMP/inuse" || true
if [[ -n "$RESOURCE_GROUP" ]]; then
  az containerapp list -g "$RESOURCE_GROUP" --query "[].properties.template.containers[].image" -o tsv 2>/dev/null \
    | sed -E 's#^[^/]+/##' >> "$TMP/inuse" || true
fi
sort -u "$TMP/inuse" -o "$TMP/inuse"
echo ">> in use:"; sed 's/^/     /' "$TMP/inuse"

deleted=0; failed=0
# One flaky call (ACR answered "connection refused" mid-run once) must not stop the cleanup.
delete() {
  local ref="$1" try
  for try in 1 2 3; do
    az acr repository delete -n "$ACR_NAME" --image "$ref" --yes -o none 2>/dev/null && return 0
    sleep $((try * 5))
  done
  echo "     ! could not delete $ref after 3 tries" >&2
  return 1
}
for repo in $(az acr repository list -n "$ACR_NAME" -o tsv); do
  az acr manifest list-metadata -r "$ACR_NAME" -n "$repo" --orderby time_desc -o json > "$TMP/m.json"
  # Tagged manifests to delete: beyond the newest KEEP, not in use, not "latest".
  python3 - "$repo" "$KEEP" "$TMP/m.json" "$TMP/inuse" > "$TMP/del" <<'PY'
import json, sys
repo, keep, mfile, ufile = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
manifests = json.load(open(mfile))
inuse = [l.strip() for l in open(ufile) if l.strip()]
tags_used = {l.split(":", 1)[1] for l in inuse if l.startswith(repo + ":")}
digests_used = {l.split("@", 1)[1] for l in inuse if l.startswith(repo + "@")}
tagged = [m for m in manifests if m.get("tags")]
for i, m in enumerate(tagged):
    tags = set(m["tags"])
    if i < keep or "latest" in tags or tags & tags_used or m["digest"] in digests_used:
        continue
    print(m["digest"], ",".join(sorted(tags)), m.get("createdTime", "")[:16])
PY
  n=$(wc -l < "$TMP/del")
  echo ">> $repo: $(python3 -c "import json;m=json.load(open('$TMP/m.json'));print(sum(1 for x in m if x.get('tags')))") tagged, $n to delete"
  while read -r digest tags created; do
    [[ -z "$digest" ]] && continue
    echo "     - $created  ${digest:7:12}  $tags"
    if [[ "$APPLY" == true ]]; then
      if delete "$repo@$digest"; then deleted=$((deleted + 1)); else failed=$((failed + 1)); fi
    fi
  done < "$TMP/del"

  # Orphaned artifacts: untagged manifests whose subject image no longer exists.
  [[ "$APPLY" == true ]] && az acr manifest list-metadata -r "$ACR_NAME" -n "$repo" -o json > "$TMP/m.json"
  python3 -c "
import json; m=json.load(open('$TMP/m.json'))
print('\n'.join(x['digest'] for x in m if not x.get('tags')))" > "$TMP/untagged"
  python3 -c "
import json; m=json.load(open('$TMP/m.json'))
print('\n'.join(x['digest'] for x in m))" > "$TMP/all"
  [[ "$APPLY" != true ]] && cut -d' ' -f1 "$TMP/del" > "$TMP/gone" || : > "$TMP/gone"
  orphans=0
  while read -r digest; do
    [[ -z "$digest" ]] && continue
    subject="$(az acr manifest show -r "$ACR_NAME" -n "$repo@$digest" --query subject.digest -o tsv 2>/dev/null || true)"
    [[ -z "$subject" || "$subject" == None ]] && continue      # no subject: part of an index, keep
    if grep -qx "$subject" "$TMP/gone" || ! grep -qx "$subject" "$TMP/all"; then
      orphans=$((orphans + 1))
      if [[ "$APPLY" == true ]]; then
        if delete "$repo@$digest"; then deleted=$((deleted + 1)); else failed=$((failed + 1)); fi
      fi
    fi
  done < "$TMP/untagged"
  (( orphans )) && echo "     + $orphans attached artifact(s) of deleted images"
done

if [[ "$APPLY" == true ]]; then
  echo ">> deleted $deleted manifest(s), $failed failed"
  (( failed == 0 ))
else
  echo ">> dry run: nothing deleted. Re-run with APPLY=true."
fi
