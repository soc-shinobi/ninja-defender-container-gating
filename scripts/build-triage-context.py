#!/usr/bin/env python3
"""Build context.md for the Copilot triage agent from a run's scan evidence.

usage: build-triage-context.py <evidence-dir> <app-dir> <out.md>

Deterministic and size-bounded: the counts and the finding list come from the reports,
not from the model, so the issue cannot overstate or understate them. Secret values never
reach the model: only Gitleaks rule, file and line are copied (the report is redacted too).
Run facts come from TRIAGE_* environment variables set by .github/workflows/copilot-triage.yml.
"""
import collections
import json
import os
import pathlib
import sys

MAX_FINDINGS = 40


def sarif_findings(path):
    if not path.exists():
        return None, []
    doc = json.loads(path.read_text(encoding="utf-8"))
    levels, rows, default = collections.Counter(), [], {}
    for run in doc.get("runs", []):
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            default[rule.get("id")] = rule.get("defaultConfiguration", {}).get("level", "warning")
        for res in run.get("results", []):
            rid = res.get("ruleId", "?")
            level = res.get("level") or default.get(rid, "warning")
            levels[level] += 1
            msg = " ".join(str(res.get("message", {}).get("text", "")).split())[:240]
            rows.append((0 if level == "error" else 1, rid, level, msg))
    rows.sort()
    return levels, rows[:MAX_FINDINGS]


def gitleaks_findings(path):
    if not path.exists():
        return None
    try:
        items = json.loads(path.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError:
        return None
    return [(i.get("RuleID", "?"), i.get("File", "?").removeprefix("/repo/"), i.get("StartLine", 0))
            for i in items][:MAX_FINDINGS]


def main():
    evidence, app, out = (pathlib.Path(a) for a in sys.argv[1:4])
    env = os.environ.get
    lines = ["# Run facts", ""]
    for label, key in (("Workflow", "TRIAGE_SOURCE"), ("Run", "TRIAGE_RUN_URL"),
                       ("Image", "TRIAGE_IMAGE"), ("Target", "TRIAGE_TARGET"),
                       ("Expected cluster outcome (confirmed only if the publish job result is success)", "TRIAGE_EXPECTED"),
                       ("Build job result", "TRIAGE_BUILD_RESULT"),
                       ("Publish job result", "TRIAGE_PUBLISH_RESULT"),
                       ("Secret scan verdict", "TRIAGE_SECRET_VERDICT"),
                       ("Image scan verdict", "TRIAGE_SCAN_VERDICT")):
        lines.append(f"- {label}: {env(key) or 'unknown'}")

    leaks = gitleaks_findings(evidence / "gitleaks-results.json")
    lines += ["", "# Gitleaks findings (redacted: rule, file, line only)", ""]
    if leaks is None:
        lines.append("No Gitleaks report in this run.")
    elif not leaks:
        lines.append("Gitleaks found no secrets.")
    else:
        lines += ["| Rule | File | Line |", "|---|---|---:|"]
        lines += [f"| {r} | {f} | {n} |" for r, f, n in leaks]

    levels, rows = sarif_findings(evidence / "image-scan.sarif")
    lines += ["", "# Defender image-scan findings", ""]
    if levels is None:
        lines.append("No Defender image-scan report in this run (scan skipped or not configured).")
    else:
        total = sum(levels.values())
        lines.append(f"Totals: {total} finding(s); error={levels.get('error', 0)}, "
                     f"warning={levels.get('warning', 0)}, note={levels.get('note', 0)}. "
                     f"Listing the first {len(rows)} (error level first).")
        lines += ["", "| Rule | Level | Message |", "|---|---|---|"]
        lines += [f"| {rid} | {lvl} | {msg.replace('|', ' ')} |" for _, rid, lvl, msg in rows]

    for name in ("Dockerfile", "requirements.txt"):
        f = app / name
        if f.exists():
            lines += ["", f"# {app.as_posix()}/{name}", "", "```", f.read_text(encoding="utf-8").rstrip(), "```"]

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
