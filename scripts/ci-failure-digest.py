#!/usr/bin/env python3
"""Daily CI failure digest: find failed workflow runs, build one Copilot context per broken
workflow, and close the issues of workflows that are green again.

usage: ci-failure-digest.py collect <out-dir>
       ci-failure-digest.py close

collect  Lists completed runs on the default branch since the window start, keeps the
         failures, and sorts each failing workflow into one of three buckets:
           broken     latest run still fails for a real reason -> <out-dir>/<slug>/context.md
                      and an entry in <out-dir>/manifest.json (one Copilot issue each)
           recovered  failed in the window, but its latest run is healthy -> no issue
           by design  every failure is a security gate that blocked as intended
                      (.github/copilot/expected-failures.json) -> no issue
close    Closes open `ci-failure` issues whose workflow's latest run is healthy again.
         Healthy = success, or a by-design gate block.

Window: WINDOW_HOURS (default 24) back from now, extended to the start of the last
successful digest run so a skipped schedule leaves no gap; never more than 7 days.
Needs GH_TOKEN (actions: read, checks: read, issues: write for close) and GH_REPO.
DRY_RUN=true makes close report instead of closing.
"""
import datetime as dt
import json
import os
import re
import subprocess
import sys

REPO = os.environ.get("GH_REPO", "")
BRANCH = os.environ.get("DIGEST_BRANCH", "main")
SELF = os.environ.get("DIGEST_WORKFLOW", ".github/workflows/ci-failure-digest.yml")
LABEL = os.environ.get("DIGEST_LABEL", "ci-failure")
KEY_PREFIX = "ci-failure/"
EXPECTED_FILE = ".github/copilot/expected-failures.json"
FAILED = {"failure", "timed_out", "startup_failure"}
MAX_RUNS_WITH_LOGS = 3      # newest unexpected failures per workflow that get log excerpts
LOG_TAIL = 80               # log lines kept per failed run
WORKFLOW_FILE_LINES = 400

# Last line of defence: GitHub already masks registered secrets as ***, but a value printed
# by a tool (a token in an error message, a SAS URL) is not registered. Strip the usual shapes.
REDACT = [
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), "<redacted-github-token>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "<redacted-jwt>"),
    (re.compile(r"(?i)(AccountKey|SharedAccessKey|sig|client_secret|password|api[-_]?key)=([^&;\s\"']+)"), r"\1=<redacted>"),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/-]{20,}=*"), r"\1<redacted>"),
]
# `gh run view --log-failed` prefixes every line with "<job>\t<step>\t<timestamp> "; the step
# name may contain spaces ("UNKNOWN STEP"), so split on tabs, not on whitespace.
TIMESTAMP = re.compile(r"^[^\t]*\t[^\t]*\t\d{4}-\d\d-\d\dT[\d:.]+Z ?")
# Colour codes arrive either as real escapes or, for some steps, as a literal "^[".
ANSI = re.compile(r"(\x1b|\^\[)\[[0-9;]*m")


def gh(*args, check=True):
    r = subprocess.run(["gh", *args], text=True, capture_output=True)
    if check and r.returncode:
        raise RuntimeError(f"gh {' '.join(args[:3])}: {r.stderr.strip()[:300]}")
    return r.stdout


def api(path, paginate=False):
    args = ["api", "-H", "Accept: application/vnd.github+json", path]
    if paginate:
        args.insert(1, "--paginate")
        args += ["--jq", ".workflow_runs[]? // .jobs[]? // .[]?"]
        return [json.loads(line) for line in gh(*args).splitlines() if line.strip()]
    return json.loads(gh(*args))


def redact(text):
    for rx, repl in REDACT:
        text = rx.sub(repl, text)
    return text


def iso(t):
    return dt.datetime.fromisoformat(t.replace("Z", "+00:00"))


def window_start():
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=float(os.environ.get("WINDOW_HOURS") or 24))
    name = os.path.basename(SELF)
    try:
        last = api(f"repos/{REPO}/actions/workflows/{name}/runs?status=success&branch={BRANCH}&per_page=1")
        runs = last.get("workflow_runs") or []
        if runs:
            start = min(start, iso(runs[0]["created_at"]))
    except RuntimeError:
        pass            # first run, or the workflow file is not on the default branch yet
    return max(start, now - dt.timedelta(days=7))


def expected_patterns():
    try:
        return json.load(open(EXPECTED_FILE, encoding="utf-8"))["patterns"]
    except (OSError, KeyError, ValueError):
        return []


def failed_jobs(run):
    """Failed jobs of a run with their failed steps and failure annotations."""
    jobs = api(f"repos/{REPO}/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    out = []
    for j in jobs:
        if j.get("conclusion") not in FAILED:
            continue
        steps = [s["name"] for s in j.get("steps") or [] if s.get("conclusion") in FAILED]
        try:
            notes = api(f"repos/{REPO}/check-runs/{j['id']}/annotations")
        except RuntimeError:
            notes = []
        errors = [{"title": (n.get("title") or "").strip(), "message": (n.get("message") or "").strip()}
                  for n in notes if n.get("annotation_level") == "failure"]
        out.append({"name": j["name"], "url": j.get("html_url", ""), "steps": steps, "errors": errors})
    return out


def by_design(jobs, patterns):
    """True when every failed job carries a failure annotation of an expected gate block."""
    def hit(err):
        return any(err["title"] == p["title"] and re.search(p["message"], err["message"], re.I)
                   for p in patterns)
    return bool(jobs) and all(any(hit(e) for e in j["errors"]) for j in jobs)


def signature(jobs):
    """One line naming the failure: the first meaningful error annotation, else the step."""
    for j in jobs:
        for e in j["errors"]:
            if not re.match(r"Process completed with exit code \d+", e["message"]):
                return redact(" ".join(f"{e['title']}: {e['message']}".strip(": ").split()))[:300]
    for j in jobs:
        if j["steps"]:
            return f"{j['name']} / {j['steps'][0]} failed"
    return "failed (no annotation)"


def latest_health(path, patterns):
    """(healthy, run) for the newest completed, non-cancelled run of a workflow on BRANCH."""
    name = os.path.basename(path)
    try:
        runs = api(f"repos/{REPO}/actions/workflows/{name}/runs?branch={BRANCH}&status=completed&per_page=10")
    except RuntimeError:
        return None, None       # workflow file removed
    for r in runs.get("workflow_runs") or []:
        if r.get("conclusion") in ("cancelled", "skipped", "neutral", None):
            continue
        if r["conclusion"] == "success":
            return True, r
        if r["conclusion"] in FAILED:
            return by_design(failed_jobs(r), patterns), r
        return False, r
    return None, None


def log_excerpt(run_id):
    raw = gh("run", "view", str(run_id), "--log-failed", "-R", REPO, check=False)
    lines = [TIMESTAMP.sub("", ANSI.sub("", ln)) for ln in raw.splitlines()]
    lines = [ln for ln in lines if ln.strip() and not ln.startswith("##[group]") and ln != "##[endgroup]"]
    return redact("\n".join(lines[-LOG_TAIL:]))


def slug(path):
    return re.sub(r"[^a-z0-9]+", "-", os.path.basename(path).lower()).strip("-")


def write_context(out_dir, path, name, failures, latest):
    d = os.path.join(out_dir, slug(path))
    os.makedirs(d, exist_ok=True)
    md = [f"# Workflow: {name}", f"- File: `{path}`", f"- Branch: `{BRANCH}`",
          f"- Failed runs in the window: {len(failures)}",
          f"- Latest run: {latest['html_url']} ({latest['conclusion']}, {latest['created_at']})", ""]
    for i, f in enumerate(failures):
        r = f["run"]
        md += [f"## Run {r['run_number']} - {r['created_at']}", f"- URL: {r['html_url']}",
               f"- Event: {r['event']}, attempt {r.get('run_attempt', 1)}, commit {r['head_sha'][:7]}",
               f"- Signature: {f['signature']}"]
        for j in f["jobs"]:
            md.append(f"- Failed job `{j['name']}`, step(s): {', '.join(j['steps']) or 'unknown'}")
            for e in j["errors"][:5]:
                md.append(f"  - error annotation: {redact((e['title'] + ': ' if e['title'] else '') + e['message'])[:500]}")
        if i < MAX_RUNS_WITH_LOGS:
            md += ["", "Log excerpt (failed steps, last lines, redacted):", "```", log_excerpt(r["id"]), "```"]
        md.append("")
    try:
        wf = open(path, encoding="utf-8").read().splitlines()[:WORKFLOW_FILE_LINES]
        md += [f"## Workflow file `{path}`", "```yaml", *wf, "```"]
    except OSError:
        md.append(f"(workflow file `{path}` not found in this checkout)")
    with open(os.path.join(d, "context.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")
    return d


def summary(lines):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    print(text)
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)


def collect(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    patterns = expected_patterns()
    start = window_start()
    since = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    runs = api(f"repos/{REPO}/actions/runs?branch={BRANCH}&status=completed&created=%3E%3D{since}&per_page=100",
               paginate=True)
    groups = {}
    for r in runs:
        path = r.get("path", "")
        # Only this repo's workflow files; dynamic Dependabot/Copilot runs and the digest itself are out.
        if not path.startswith(".github/workflows/") or path == SELF or r.get("conclusion") not in FAILED:
            continue
        groups.setdefault(path, {"name": r["name"], "runs": []})["runs"].append(r)

    manifest, rows = [], []
    for path, g in sorted(groups.items()):
        failures, designed = [], 0
        for r in sorted(g["runs"], key=lambda x: x["created_at"], reverse=True):
            jobs = failed_jobs(r)
            if by_design(jobs, patterns):
                designed += 1
            else:
                failures.append({"run": r, "jobs": jobs, "signature": signature(jobs)})
        healthy, latest = latest_health(path, patterns)
        newest = g["runs"][0]["html_url"] if g["runs"] else ""
        if not failures:
            rows.append(f"| 🛡️ blocked by design | {g['name']} | {designed} | gate stopped the run as intended | [latest]({newest}) |")
        elif healthy:
            rows.append(f"| ✅ recovered | {g['name']} | {len(failures)} | latest run is green again | [latest]({latest['html_url']}) |")
        elif latest is None:
            rows.append(f"| ⚪ removed | {g['name']} | {len(failures)} | workflow file no longer on `{BRANCH}` | |")
        else:
            d = write_context(out_dir, path, g["name"], failures, latest)
            sigs = sorted({f["signature"] for f in failures})
            manifest.append({"key": KEY_PREFIX + path, "workflow": g["name"], "path": path, "dir": d,
                             "failed_runs": len(failures), "signatures": sigs})
            rows.append(f"| ❌ broken | {g['name']} | {len(failures)} | {sigs[0][:120].replace('|', '/')} | "
                        f"[latest]({latest['html_url']}) |")

    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    lines = [f"### 🩺 CI failure digest · `{BRANCH}` since {since}", ""]
    if rows:
        lines += ["| State | Workflow | Failed runs | Cause | Run |", "|---|---|---:|---|---|", *rows]
    else:
        lines.append("✅ No failed workflow runs in the window.")
    lines += ["", f"{len(manifest)} workflow(s) need an issue."]
    summary(lines)
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"broken={len(manifest)}\n")


def close():
    patterns = expected_patterns()
    dry = os.environ.get("DRY_RUN", "false").lower() == "true"
    issues = json.loads(gh("issue", "list", "-R", REPO, "--label", LABEL, "--state", "open",
                           "--limit", "100", "--json", "number,title,body,url"))
    lines, closed = [], 0
    for i in issues:
        m = re.search(r"<!--\s*copilot-triage-key:\s*" + re.escape(KEY_PREFIX) + r"(\S+)\s*-->", i.get("body") or "")
        if not m:
            continue
        path = m.group(1)
        healthy, latest = latest_health(path, patterns)
        if latest is None:
            reason = f"`{path}` no longer exists on `{BRANCH}`."
        elif healthy:
            reason = f"latest run of `{path}` is green again: {latest['html_url']}"
        else:
            lines.append(f"- ⏳ still failing: [#{i['number']}]({i['url']}) {i['title']}")
            continue
        closed += 1
        lines.append(f"- {'🔍 would close' if dry else '✅ closed'}: [#{i['number']}]({i['url']}) - {reason}")
        if not dry:
            gh("issue", "close", str(i["number"]), "-R", REPO, "--reason", "completed",
               "--comment", f"Closed by the CI failure digest: {reason}")
    if lines:
        summary(["### 🧹 Open ci-failure issues", *lines])
    print(f"{closed} issue(s) {'would be ' if dry else ''}closed")


if __name__ == "__main__":
    if not REPO:
        sys.exit("GH_REPO is not set")
    if len(sys.argv) == 3 and sys.argv[1] == "collect":
        collect(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] == "close":
        close()
    else:
        sys.exit(__doc__)
