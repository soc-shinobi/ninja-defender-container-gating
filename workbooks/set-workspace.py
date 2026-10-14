#!/usr/bin/env python3
"""Bind a workbook to the Sentinel workspace it will be saved into.

Why this exists: a workbook with an empty `fallbackResourceIds` and no `context.ownerId` has no
resource to be saved against, and the portal refuses to apply or save it - with no useful error.
Every working Sentinel/Defender workbook carries:

  "context":             { "ownerId": "<workspace resource id>" }
  "fallbackResourceIds": [ "<workspace resource id>" ]

and each query item that uses the Advanced Hunting data source carries the same id in
`crossComponentResources` (that is exactly what the portal writes into an item when you pick the
data source by hand).

Find the id with:
  az monitor log-analytics workspace show -g <rg> -n <name> --query id -o tsv

Usage:
  python3 workbooks/set-workspace.py <workspaceResourceId> [workbook.json]
  python3 workbooks/set-workspace.py --clear [workbook.json]     # strip it again before sharing
"""
import json
import pathlib
import sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
clear = "--clear" in sys.argv
ws = None if clear else args[0]
path = pathlib.Path(args[-1] if len(args) > (0 if clear else 1)
                    else pathlib.Path(__file__).parent / "aks-cluster-fingerprint.workbook.json")
wb = json.loads(path.read_text(encoding="utf-8"))

wb.pop("isLocked", None)              # not present in working portal exports
wb.setdefault("styleSettings", {})
if clear:
    wb.pop("context", None)
    wb["fallbackResourceIds"] = []
else:
    wb["context"] = {"ownerId": ws}
    wb["fallbackResourceIds"] = [ws]

def walk(items):
    n = 0
    for it in items:
        if it.get("type") == 12:
            n += walk(it["content"]["items"])
        elif it.get("type") == 3 and it["content"].get("queryType") == "advancedHunting":
            if clear:
                it["content"].pop("crossComponentResources", None)
            else:
                it["content"]["crossComponentResources"] = [ws]
            n += 1
        elif it.get("type") == 9:
            for pm in it["content"]["parameters"]:
                if pm.get("queryType") == "advancedHunting":
                    if clear:
                        pm.pop("crossComponentResources", None)
                    else:
                        pm["crossComponentResources"] = [ws]
                    n += 1
    return n

touched = walk(wb["items"])
path.write_text(json.dumps(wb, indent=2), encoding="utf-8")
print(f"{'cleared' if clear else 'bound to ' + ws} — {touched} advanced hunting queries updated -> {path}")
