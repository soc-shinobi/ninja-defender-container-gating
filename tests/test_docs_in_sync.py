"""Checks that documentation quoting code still matches the code.

ACA-readme.md reproduces infra/modules/aca-network.bicep in full so the note stands
alone in someone's notes folder. A copy like that rots silently: the module changes,
the note keeps showing the old rules, and the reader trusts the note.

Pure stdlib. Run:  make test
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(f"  {'ok  ' if condition else 'FAIL'}  {message}")
    if not condition:
        failures.append(message)


def main() -> int:
    print("docs in sync")

    doc = (ROOT / "ACA-readme.md").read_text(encoding="utf-8")
    module = (ROOT / "infra" / "modules" / "aca-network.bicep").read_text(encoding="utf-8")
    blocks = re.findall(r"```bicep\n(.*?)```", doc, re.S)

    check(len(blocks) >= 1, "ACA-readme.md contains a bicep block")
    if blocks:
        check(
            blocks[0] == module,
            "the first bicep block is byte-identical to infra/modules/aca-network.bicep",
        )

    # The flag must stay off by default: turning it on costs real money every month.
    param_file = (ROOT / "infra" / "main.bicepparam").read_text(encoding="utf-8")
    main_bicep = (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")
    check(
        "param enableAcaVnet bool = false" in main_bicep,
        "enableAcaVnet defaults to false in main.bicep",
    )
    check(
        "readEnvironmentVariable('ENABLE_ACA_VNET', 'false')" in param_file,
        "the parameter file defaults ENABLE_ACA_VNET to false",
    )

    check(
        "readEnvironmentVariable('DEPLOY_FLUX', 'true')" in param_file,
        "Flux defaults to enabled",
    )
    check(
        "param acaLocation string = location" in main_bicep
        and "param acaEnvironmentName string" in main_bicep,
        "ACA location and environment name are independent parameters",
    )
    check(
        (ROOT / "infra" / "aca.bicep").exists()
        and (ROOT / "scripts" / "deploy-aca.sh").exists(),
        "targeted ACA fallback template and script exist",
    )
    deploy_script = (ROOT / "scripts" / "deploy.sh").read_text(encoding="utf-8")
    check(
        "ManagedEnvironmentNoAvailableCapacityInRegion" in deploy_script,
        "deployment fallback is limited to the ACA capacity error",
    )
    check(
        "grant-controlpanel-access.sh" in deploy_script
        and "verify-deployment.sh" in deploy_script,
        "deployment runs panel access and end-to-end verification",
    )
    deploy_workflow = (ROOT / ".github" / "workflows" / "deploy-lab.yml").read_text(encoding="utf-8")
    check(
        "Entra user UPN or object ID" in deploy_workflow
        and "az ad user show --id" in deploy_workflow
        and "ADMIN_PRINCIPAL_ID=$OBJECT_ID" in deploy_workflow,
        "deploy workflow resolves an Entra user UPN to the object ID required by Bicep",
    )

    blocked = (ROOT / "app" / "k8s" / "x-mdc-blocked" / "deployment.yaml").read_text(encoding="utf-8")
    allowed = (ROOT / "app" / "k8s" / "x-mdc-allowed" / "deployment.yaml").read_text(encoding="utf-8")
    check(
        "namespace: x-mdc-blocked" in blocked
        and "namespace: x-mdc-allowed" in allowed,
        "Flux deploys the same sample app to blocked and allowed namespaces",
    )
    check(
        "type: LoadBalancer" in allowed and "targetPort: 8080" in allowed,
        "the allowed sample app has a public LoadBalancer service",
    )
    check(
        'azure.workload.identity/use: "true"' in allowed
        and "serviceAccountName: aks-webapp" in allowed
        and "sensitive-storage" in allowed,
        "the public AKS app uses workload identity and the sensitive-storage configuration",
    )

    workload = (ROOT / "infra" / "modules" / "workload.bicep").read_text(encoding="utf-8")
    storage_setup = (
        ROOT / "infra" / "postdeploy" / "configure-sensitive-storage.sh"
    ).read_text(encoding="utf-8")
    webapp = (ROOT / "app" / "webapp" / "app.py").read_text(encoding="utf-8")
    check(
        "Microsoft.Storage/storageAccounts" in workload
        and "storageBlobDataReaderRoleId" in workload
        and "system:serviceaccount:x-mdc-allowed:aks-webapp" in workload,
        "Blob storage, least-privilege RBAC and AKS federated identity are deployed",
    )
    check(
        "fake-sensitive-data.json" in storage_setup
        and "--allow-shared-key-access false" in storage_setup
        and (ROOT / "demo-data" / "fake-sensitive-data.json").exists(),
        "post-deploy seeds tracked fake data and disables Shared Key authorization",
    )
    check(
        "/api/connections" in webapp
        and "azure.storage.blob" in webapp
        and "Application connections" in webapp,
        "the AKS web app retrieves and displays Blob data with connection status",
    )

    workflows = ROOT / ".github" / "workflows"
    blocked_workflow = (workflows / "demo-admission-blocked.yml").read_text(encoding="utf-8")
    allowed_workflow = (workflows / "demo-admission-allowed.yml").read_text(encoding="utf-8")
    scan_workflow = (workflows / "demo-pipeline-scan-blocked.yml").read_text(encoding="utf-8")
    check(
        "workflow_dispatch:" in blocked_workflow
        and "workflow_dispatch:" in allowed_workflow
        and "workflow_dispatch:" in scan_workflow,
        "all three admission demo workflows are manual-only",
    )
    check(
        all("defender scan image" in w and "--defender-break" not in w
            for w in (blocked_workflow, allowed_workflow)),
        "namespace admission workflows scan the image report-only (never break)",
    )
    check(
        all("Gitleaks secret scan" in w and "skip_secret_findings:" in w
            and "default: true" in w.split("skip_secret_findings:")[1].split("skip_approval:")[0]
            for w in (blocked_workflow, allowed_workflow)),
        "namespace admission workflows run Gitleaks and continue on findings by default",
    )
    triage = (workflows / "copilot-triage.yml").read_text(encoding="utf-8")
    agent_step = triage.split("Copilot CLI writes issue.md")[1].split("- name:")[0]
    check(
        all("copilot_issue:" in (workflows / w).read_text(encoding="utf-8")
            and "default: false" in (workflows / w).read_text(encoding="utf-8").split("copilot_issue:")[1].split("skip_approval:")[0]
            and "uses: ./.github/workflows/copilot-triage.yml" in (workflows / w).read_text(encoding="utf-8")
            for w in ("demo-admission-allowed.yml", "demo-admission-blocked.yml",
                      "demo-pipeline-scan-blocked.yml")),
        "Copilot triage is optional (copilot_issue, default off) in all three delivery workflows",
    )
    check(
        "--deny-tool shell" in agent_step and "--deny-tool url" in agent_step
        and 'write($PWD/issue.md)' in agent_step and 'COPILOT_OFFLINE: "true"' in agent_step
        and "GH_TOKEN" not in agent_step and "github.token" not in agent_step,
        "Copilot triage agent writes only issue.md, offline, with no shell, URLs or GitHub token",
    )
    check(
        "COPILOT_FOUNDRY_API_KEY" in triage and "get-access-token --resource https://cognitiveservices.azure.com" in triage,
        "Copilot triage supports both API-key and Entra ID model auth",
    )
    for name, workflow in (("blocked", blocked_workflow), ("allowed", allowed_workflow)):
        check(
            "validate-build:" in workflow
            and "needs: validate-build" in workflow
            and workflow.index("validate-build:") < workflow.index("  publish:"),
            f"{name} admission demo separates validate/build from publish",
        )
        check(
            "environment:\n      name: showcase" in workflow
            and "contents: write\n      id-token: write" in workflow,
            f"{name} admission publish waits for showcase approval and scopes write permissions",
        )
        check(
            "skip_approval:" in workflow
            and "inputs.skip_approval == true || needs.approval.result == 'success'" in workflow
            and "if: ${{ inputs.skip_approval == true }}" in workflow
            and "Approval BYPASSED" in workflow,
            f"{name} admission demo publishes through an explicit visible approval bypass",
        )
        check(
            "anchore/sbom-action@" in workflow
            and "aks-webapp.spdx.json" in workflow
            and "SBOM: **SPDX JSON**" in workflow,
            f"{name} admission demo generates, uploads and summarizes an SPDX SBOM",
        )
        check(
            "scripts/summarize-sbom.py" in workflow,
            f"{name} admission demo includes its SBOM package inventory in the GitHub summary",
        )
    check(
        scan_workflow.index("defender scan image") < scan_workflow.index("uses: azure/login@"),
        "Defender image scanning precedes Azure login, push and deployment",
    )
    aca_workflow = (workflows / "aca-webapp.yml").read_text(encoding="utf-8")
    for name, workflow in (("pipeline demo", scan_workflow), ("ACA", aca_workflow)):
        check(
            "skip_secret_findings:" in workflow
            and "zricethezav/gitleaks@sha256:" in workflow,
            f"{name} workflow has a default-blocking Gitleaks gate with an explicit bypass",
        )
        check(
            "Redacted Gitleaks findings" in workflow
            and "Secret values are redacted and deliberately omitted" in workflow
            and ".Secret" not in workflow,
            f"{name} workflow prints redacted Gitleaks metadata without secret values",
        )
        check(
            workflow.index("Gitleaks secret gate") < workflow.index("docker build"),
            f"{name} workflow scans the Docker build context before building",
        )
        check(
            "environment:\n      name: showcase" in workflow,
            f"{name} workflow protects release/deployment with showcase approval",
        )
        check(
            "skip_approval:" in workflow
            and "needs.approval.result == 'skipped'" in workflow
            and "Approval BYPASSED" in workflow,
            f"{name} workflow supports a visible manual approval bypass",
        )
        check(
            "anchore/sbom-action@" in workflow
            and "actions/attest-build-provenance@" in workflow,
            f"{name} workflow emits an SBOM and can create signed provenance",
        )
        check(
            "SBOM: **SPDX JSON**" in workflow
            and "included in build artifact" in workflow,
            f"{name} workflow reports its SBOM in the GitHub summary",
        )
        check(
            "scripts/summarize-sbom.py" in workflow,
            f"{name} workflow includes the SBOM package inventory in the GitHub summary",
        )
        check(
            "enable_attestations:" in workflow
            and "default: false" in workflow
            and "GitHub attestations disabled" in workflow,
            f"{name} workflow makes GitHub attestations opt-in for private repositories",
        )
    check(
        'defender scan image "aca-webapp-scan:$TAG"' in aca_workflow
        and "local/aca-webapp" not in aca_workflow,
        "ACA Defender scan uses a slash-free local Docker tag",
    )
    check(
        'defender scan image "aks-webapp-scan:$TAG"' in scan_workflow
        and "local/aks-webapp" not in scan_workflow,
        "pipeline demo Defender scan uses a slash-free local Docker tag",
    )
    defender_workflow = (workflows / "security-defender-scan-only.yml").read_text(encoding="utf-8")
    check(
        "defender-image-${{ matrix.image }}.spdx.json" in defender_workflow
        and "scripts/summarize-sbom.py" in defender_workflow
        and "Keep the SBOM and SARIF as a run artifact" in defender_workflow,
        "repository image scan generates, summarizes and uploads its SPDX SBOM",
    )
    check(
        "context: ./app/webapp" in defender_workflow
        and "context: ./app/aks-webapp" in defender_workflow,
        "repository image scan covers both the aca-webapp and aks-webapp images",
    )
    check(
        "checkov==$CHECKOV_VERSION" in defender_workflow
        and "--soft-fail" in defender_workflow
        and "--framework bicep kubernetes" in defender_workflow,
        "repository IaC scan runs pinned checkov report-only on Bicep and Kubernetes",
    )
    flux_wait = (ROOT / "scripts" / "wait-flux-reconciliation.sh").read_text(encoding="utf-8")
    misconfig_workflow = (workflows / "demo-misconfig.yml").read_text(encoding="utf-8")
    check(
        "powerState.code" in flux_wait
        and '"$AKS_POWER_STATE" != Running' in flux_wait
        and "Flux cannot reconcile workloads" in flux_wait,
        "shared Flux wait fails immediately when AKS is not Running",
    )
    check(
        'FLUX_WAIT_TIMEOUT_SECONDS:-600' in flux_wait
        and 'FLUX_WAIT_POLL_SECONDS:-10' in flux_wait
        and 'FLUX_SOURCE_ERROR_GRACE_SECONDS:-120' in flux_wait,
        "shared Flux wait defaults to 10 minutes, polling every 10 seconds with 2-minute source grace",
    )
    check(
        'contains_commit "$LAST_APPLIED_REVISION"' in flux_wait
        and "merge-base --is-ancestor" in flux_wait,
        "shared Flux wait matches the Kustomization revision, accepting later commits",
    )
    check(
        "EXPECTED_DENIAL_PATTERN" in flux_wait
        and "not because admission denied it" in flux_wait,
        "shared Flux wait only accepts NotReady when admission denied the workload",
    )
    check(
        "DISCLAIMER" in flux_wait
        and all("demo check, not a gate" in (workflows / w).read_text(encoding="utf-8")
                for w in ("demo-admission-allowed.yml", "demo-admission-blocked.yml",
                          "demo-pipeline-scan-blocked.yml")),
        "Flux wait carries its demo-check disclaimer in the script and every calling workflow",
    )
    check(
        "powerState.code" in misconfig_workflow
        and '"$AKS_POWER_STATE" != Running' in misconfig_workflow
        and "for _ in $(seq 1 60)" in misconfig_workflow
        and "sleep 10" in misconfig_workflow,
        "misconfiguration Flux wait checks AKS and uses the same 10-minute maximum",
    )

    # Denying Azure DNS breaks the environment in a way that looks like something else.
    check(
        "168.63.129.16" in module and "'Deny'" in module,
        "the module allows Azure DNS explicitly alongside its deny-all rule",
    )
    deny_priority = re.search(r"name: 'Deny-All-Outbound'.*?priority: (\d+)", module, re.S)
    allow_priorities = [int(p) for p in re.findall(r"priority: (\d+)", module)]
    if deny_priority:
        dp = int(deny_priority.group(1))
        check(
            dp == max(allow_priorities),
            f"the deny-all rule has the highest (weakest) priority number, {dp}",
        )

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
