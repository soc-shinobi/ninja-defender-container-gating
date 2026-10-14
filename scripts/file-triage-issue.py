#!/usr/bin/env python3
"""File the issue Copilot wrote: the "safe output" half of the triage.

usage: file-triage-issue.py <issue.md> <triage-key>

The agent only writes issue.md and never holds a GitHub token. This step, which does, files
it: one open issue per triage key (label `copilot-triage` plus a hidden key marker), so a
re-run edits the existing issue and adds a comment instead of opening a duplicate.
Needs GH_TOKEN (issues: write) and GH_REPO. Footer facts come from TRIAGE_* variables.
Shared by two flows: security triage (default label and footer) and the CI failure digest,
which sets TRIAGE_LABEL, TRIAGE_LABEL_DESC and TRIAGE_EVIDENCE.
"""
import json
import os
import re
import subprocess
import sys

LABEL = os.environ.get("TRIAGE_LABEL", "copilot-triage")
LABEL_DESC = os.environ.get("TRIAGE_LABEL_DESC",
                            "Security triage written by GitHub Copilot from pipeline scan results")
MAX_BODY = 60000


def gh(*args, stdin=None):
    return subprocess.run(["gh", *args], input=stdin, text=True, check=True,
                          capture_output=True).stdout


def parse(path):
    text = open(path, encoding="utf-8").read().strip()
    first, _, rest = text.partition("\n")
    m = re.match(r"\s*TITLE:\s*(.+)", first)
    if not m or not rest.strip():
        sys.exit(f"::error title=Copilot triage::{path} does not start with a TITLE: line and a body")
    title = " ".join(m.group(1).split())[:120]
    # The agent was told not to @-mention anyone; enforce it rather than trust it.
    body = re.sub(r"(?<![\w`])@(?=[A-Za-z0-9])", "@​", rest.strip())
    # The dedup marker is ours: drop any the model wrote, so its text cannot claim (and on
    # the next run, take over) another triage key's issue.
    body = re.sub(r"<!--\s*copilot-triage-key:.*?-->", "", body, flags=re.S)
    return title, body


def main():
    path, key = sys.argv[1], sys.argv[2]
    title, body = parse(path)
    env = os.environ.get
    marker = f"<!-- copilot-triage-key: {key} -->"
    footer = (
        f"\n\n---\n"
        f"> [!NOTE]\n"
        f"> Written by GitHub Copilot CLI on a custom model (`{env('TRIAGE_MODEL', 'unknown')}`), "
        f"from {env('TRIAGE_EVIDENCE', 'the scan evidence of')} [this run]({env('TRIAGE_RUN_URL', '')}). "
        f"AI-generated: verify findings and versions before acting. Counts come from the "
        f"{'run data' if env('TRIAGE_EVIDENCE') else 'reports'}, not the model.\n\n"
        f"{marker}\n"
    )
    body = body[: MAX_BODY - len(footer)] + footer

    gh("label", "create", LABEL, "--color", "8250df", "--force",
       "--description", LABEL_DESC)
    existing = json.loads(gh("issue", "list", "--label", LABEL, "--state", "open",
                             "--limit", "100", "--json", "number,body,url"))
    match = next((i for i in existing if marker in (i.get("body") or "")), None)
    if match:
        gh("issue", "edit", str(match["number"]), "--title", title, "--body-file", "-", stdin=body)
        gh("issue", "comment", str(match["number"]), "--body",
           f"Updated by Copilot triage from [run]({env('TRIAGE_RUN_URL', '')}).")
        url, verb = match["url"], "updated"
    else:
        url = gh("issue", "create", "--title", title, "--label", LABEL, "--body-file", "-",
                 stdin=body).strip()
        verb = "created"
    print(f"::notice title=Copilot triage issue {verb}::{url}")
    summary = env("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### 🤖 Copilot triage issue {verb}\n- [{title}]({url})\n")


if __name__ == "__main__":
    main()
