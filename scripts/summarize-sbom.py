#!/usr/bin/env python3
"""Append a compact SPDX JSON package inventory to the GitHub job summary."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def cell(value: object) -> str:
    text = str(value or "—").replace("\r", " ").replace("\n", " ")
    return text.replace("|", "\\|").replace("`", "\\`")


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(f"usage: {sys.argv[0]} <spdx.json> [artifact-name]", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    artifact = sys.argv[2] if len(sys.argv) == 3 else path.name
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        print("GITHUB_STEP_SUMMARY is not set", file=sys.stderr)
        return 2

    document = json.loads(path.read_text(encoding="utf-8"))
    packages = document.get("packages") or []
    packages = sorted(
        packages,
        key=lambda package: (
            str(package.get("name", "")).casefold(),
            str(package.get("versionInfo", "")).casefold(),
        ),
    )
    limit = 50

    lines = [
        "### 📦 Software Bill of Materials",
        "",
        f"- Format: **SPDX JSON**",
        f"- Packages: **{len(packages)}**",
        f"- Complete document: `{cell(artifact)}` in the uploaded build artifact",
        "",
        "<details><summary>Package inventory (first 50)</summary>",
        "",
        "| Package | Version | Type | License |",
        "|---|---|---|---|",
    ]
    for package in packages[:limit]:
        lines.append(
            "| {name} | {version} | {kind} | {license} |".format(
                name=cell(package.get("name")),
                version=cell(package.get("versionInfo")),
                kind=cell(package.get("primaryPackagePurpose")),
                license=cell(
                    package.get("licenseConcluded")
                    or package.get("licenseDeclared")
                ),
            )
        )
    if len(packages) > limit:
        lines.extend(("", f"_Showing {limit} of {len(packages)} packages._"))
    lines.extend(("", "</details>", ""))

    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
