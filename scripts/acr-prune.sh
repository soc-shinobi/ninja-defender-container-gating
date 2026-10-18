#!/usr/bin/env bash
# Prune the lab registry: per repository keep the newest KEEP image digests and delete the
# rest, together with the artifacts attached to them.
#
#   bash scripts/acr-prune.sh            # dry run: prints what would be deleted
#   APPLY=true bash scripts/acr-prune.sh # deletes
#
# What counts as an image digest: every manifest that is not an artifact attached to another
# one (no OCI "subject") and not a platform entry inside an image index - tagged or not.
# Tags do not matter: "latest" lives on the newest digest anyway (each publishing workflow
# moves it there), and an old digest goes even if it still carries a tag.
#
# One exception: a digest still in use is never deleted, even when it is older than the
# newest KEEP - deleting it would break the running workload on its next pull. In use means
# referenced by the Flux paths (app/k8s/{base,x-mdc-*}), by tag or digest, or run by a
# Container App in RESOURCE_GROUP. Normally those are among the newest KEEP anyway.
#
# Attached artifacts (Defender security findings, signatures) are deleted with their image;
# ACR usually does that itself, the orphan pass catches the rest.
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
echo ">> acr-prune $ACR_NAME · keep newest $KEEP image digests per repository · $mode"

# ---- in use: what Flux deploys and what the Container Apps run -------------
: > "$TMP/inuse"
for dir in "$ROOT"/app/k8s/base "$ROOT"/app/k8s/x-mdc-*; do
  grep -rhoE 'image:[[:space:]]*[^[:space:]]+' "$dir" \
    | sed -E 's/^image:[[:space:]]*//; s#^[^/]+/##' >> "$TMP/inuse" || true
done
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
  # Untagged manifests and image indexes need their content: subject (attached artifact) and,
  # for an index, the platform manifests it lists.
  mkdir -p "$TMP/show"; rm -f "$TMP"/show/*
  python3 -c "
import json; m=json.load(open('$TMP/m.json'))
print('\n'.join(x['digest'] for x in m if not x.get('tags') or 'list' in x.get('mediaType','') or 'index' in x.get('mediaType','')))" \
  | while read -r d; do
      [[ -z "$d" ]] && continue
      az acr manifest show -r "$ACR_NAME" -n "$repo@$d" -o json > "$TMP/show/${d#sha256:}.json" 2>/dev/null || echo '{}' > "$TMP/show/${d#sha256:}.json"
    done

  python3 - "$repo" "$KEEP" "$TMP/m.json" "$TMP/inuse" "$TMP/show" > "$TMP/plan" <<'PY'
import json, os, sys
repo, keep, mfile, ufile, showdir = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
manifests = json.load(open(mfile))                       # newest first
inuse = [l.strip() for l in open(ufile) if l.strip()]
tags_used = {l.split(":", 1)[1] for l in inuse if l.startswith(repo + ":")}
digests_used = {l.split("@", 1)[1] for l in inuse if l.startswith(repo + "@")}

def show(d):
    p = os.path.join(showdir, d.split(":", 1)[1] + ".json")
    return json.load(open(p)) if os.path.exists(p) else {}

subject = {m["digest"]: (show(m["digest"]).get("subject") or {}).get("digest") for m in manifests}
children = {c["digest"] for m in manifests for c in (show(m["digest"]).get("manifests") or [])}
# A tagged manifest is always an image, even when an index also lists it.
images = [m for m in manifests if not subject.get(m["digest"])
          and (m.get("tags") or m["digest"] not in children)]

keep_set = set()
for i, m in enumerate(images):
    tags = set(m.get("tags") or [])
    if i < keep or tags & tags_used or m["digest"] in digests_used:
        keep_set.add(m["digest"])
# Platform entries of a kept index stay with it.
for m in images:
    if m["digest"] in keep_set:
        keep_set |= {c["digest"] for c in (show(m["digest"]).get("manifests") or [])}

drop = [m for m in images if m["digest"] not in keep_set]
gone = {m["digest"] for m in drop}
all_digests = {m["digest"] for m in manifests}
orphans = [d for d, s in subject.items() if s and (s in gone or s not in all_digests)]

print(f"COUNT {len(images)} {len(drop)} {len(orphans)}")
for m in drop:
    print("IMAGE", m["digest"], m.get("createdTime", "")[:16], ",".join(sorted(m.get("tags") or [])) or "(untagged)")
for d in orphans:
    print("ORPHAN", d)
PY

  read -r _ n_images n_drop n_orph < <(grep '^COUNT' "$TMP/plan")
  echo ">> $repo: $n_images image digest(s), $n_drop to delete"
  while read -r _ digest created tags; do
    echo "     - $created  ${digest:7:12}  $tags"
    if [[ "$APPLY" == true ]]; then
      if delete "$repo@$digest"; then deleted=$((deleted + 1)); else failed=$((failed + 1)); fi
    fi
  done < <(grep '^IMAGE' "$TMP/plan")
  # ACR removes most attached artifacts together with their image; delete what is left.
  if (( n_orph )); then
    echo "     + $n_orph attached artifact(s) of deleted images"
    if [[ "$APPLY" == true ]]; then
      while read -r _ digest; do
        az acr manifest show -r "$ACR_NAME" -n "$repo@$digest" -o none 2>/dev/null || continue  # already gone
        if delete "$repo@$digest"; then deleted=$((deleted + 1)); else failed=$((failed + 1)); fi
      done < <(grep '^ORPHAN' "$TMP/plan")
    fi
  fi
done

if [[ "$APPLY" == true ]]; then
  echo ">> deleted $deleted manifest(s), $failed failed"
  (( failed == 0 ))
else
  echo ">> dry run: nothing deleted. Re-run with APPLY=true."
fi
