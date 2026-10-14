#!/usr/bin/env python3
"""Rewrite the data source of every query and parameter in a workbook.

Why this exists: a workbook JSON carries its data source as `queryType` on EVERY query
item and EVERY query-backed parameter. Get it wrong and the tables are simply not there -
and because these queries use `union isfuzzy=true`, that does not even raise "table not
found". The union collapses to an empty schema and the portal reports

    failed to resolve scalar expression named 'AzureResourceId'
    filter expression should be boolean

which reads like a broken query and is actually a wrong data source. The cluster picker
is a parameter, so it fails the same way while the panels look innocent.

For this workbook the correct value is the STRING "advancedHunting" (verified in the
Defender portal, 2026-09-21). Integers are Azure Monitor's own providers - 0 Logs,
1 Azure Resource Graph - and 1 is what a workbook defaults to, which is why a pasted
workbook silently runs its Kusto against Resource Graph.

    python3 workbooks/set-datasource.py advancedHunting
    python3 workbooks/set-datasource.py advancedHunting --workspace-param

--workspace-param additionally pins every query to `crossComponentResources:
["{Workspace}"]` and adds a workspace picker. Only needed if the portal complains that a
query has no workspace; the Defender portal normally supplies its own.
"""
import json
import pathlib
import sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
flags = {a for a in sys.argv[1:] if a.startswith("--")}
raw = args[0]
qt = int(raw) if raw.lstrip("-").isdigit() else raw
path = pathlib.Path(args[1] if len(args) > 1
                    else pathlib.Path(__file__).parent / "aks-cluster-fingerprint.workbook.json")
wb = json.loads(path.read_text(encoding="utf-8"))

WORKSPACE_PARAM = {
    "id": "p-workspace",
    "version": "KqlParameterItem/1.0",
    "name": "Workspace",
    "label": "Workspace",
    "type": 5,
    "isRequired": True,
    "value": None,
    "typeSettings": {"resourceTypeFilter": {"microsoft.operationalinsights/workspaces": True},
                     "additionalResourceOptions": ["value::1"]},
}

queries = params = 0
for item in wb["items"]:
    if item["type"] == 3:
        item["content"]["queryType"] = qt
        if "--workspace-param" in flags:
            item["content"]["crossComponentResources"] = ["{Workspace}"]
        else:
            item["content"].pop("crossComponentResources", None)
        queries += 1
    elif item["type"] == 9:
        item["content"]["queryType"] = qt
        names = [pm["name"] for pm in item["content"]["parameters"]]
        if "--workspace-param" in flags and "Workspace" not in names:
            item["content"]["parameters"].insert(0, WORKSPACE_PARAM)
        for pm in item["content"]["parameters"]:
            if pm.get("query"):
                pm["queryType"] = qt
                if "--workspace-param" in flags:
                    pm["crossComponentResources"] = ["{Workspace}"]
                params += 1

path.write_text(json.dumps(wb, indent=2), encoding="utf-8")
print(f"queryType={qt!r} applied to {queries} query panels and {params} parameter queries -> {path}")
