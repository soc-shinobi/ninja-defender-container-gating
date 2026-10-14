#!/usr/bin/env python3
"""Markdown summary of a SARIF report: findings by severity and the top rules.

usage: summarize-sarif.py <report.sarif> <title>
Writes to stdout and, inside GitHub Actions, appends to $GITHUB_STEP_SUMMARY. Never fails
the step: a missing report is reported as such (scan skipped or failed before output).
"""
import json,sys,os,collections
sarif,gate=sys.argv[1],sys.argv[2]
out=os.environ.get("GITHUB_STEP_SUMMARY")
def emit(s):
    print(s)
    if out:
        open(out,"a").write(s+"\n")
if not os.path.exists(sarif):
    emit(f"### ⚪ {gate} — no SARIF report was produced (scan skipped or failed before output)\n")
    sys.exit(0)
d=json.load(open(sarif))
lvl=collections.Counter(); rules=collections.Counter(); where={}; dflt={}
for run in d.get("runs",[]):
    for r in run.get("tool",{}).get("driver",{}).get("rules",[]):
        dflt[r.get("id")]=r.get("defaultConfiguration",{}).get("level","warning")
    for res in run.get("results",[]):
        rid=res.get("ruleId","?"); l=res.get("level") or dflt.get(rid,"warning")
        lvl[l]+=1; rules[rid]+=1
        if rid not in where:
            loc=res.get("locations") or [{}]
            where[rid]=loc[0].get("physicalLocation",{}).get("artifactLocation",{}).get("uri","")
total=sum(lvl.values())
icon="🔴" if lvl.get("error") else ("🟠" if lvl.get("warning") else "🟢")
emit(f"### {icon} {gate}  _(report-only)_\n")
emit("| Severity | Count |\n|---|---:|")
for k,label in (("error","🔴 error"),("warning","🟠 warning"),("note","🔵 note")):
    emit(f"| {label} | {lvl.get(k,0)} |")
emit(f"| **total** | **{total}** |\n")
if rules:
    emit("| Rule / CVE | Hits | Example location |\n|---|---:|---|")
    for rid,n in rules.most_common(12):
        emit(f"| `{rid}` | {n} | `{where.get(rid,'')}` |")
print(f"::notice title={gate}::{total} finding(s), {lvl.get('error',0)} error-level (report-only, not breaking)")
