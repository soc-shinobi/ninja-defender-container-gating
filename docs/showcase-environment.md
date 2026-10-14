# Showcase deployment approval

The security-focused workflows pause at a dedicated approval job protected by the GitHub
environment named `showcase`. Configure the environment once before running the demo.
Environment protection is repository configuration and cannot be declared in workflow YAML.

## Private repository: no gate yet

GitHub offers required reviewers on private repositories only with GitHub Enterprise
(*"If you are on a GitHub Free, GitHub Pro, or GitHub Team plan, required reviewers are only
available for public repositories."*). While this repository is private, `showcase` has no
protection rules: the approval jobs run, pass at once, and `scripts/record-approval.sh` writes
**⚪ Showcase approval not enforced** to the run summary instead of claiming an approval.
Nothing breaks and no workflow needs a change.

## Configure GitHub (public repository)

After making the repository public, run once:

```bash
make approval-gate                                     # you as the reviewer
APPROVERS=alice,bob PREVENT_SELF_REVIEW=true make approval-gate
```

`scripts/setup-approval-gate.sh` sets the required reviewers on `showcase` and restricts
deployments to `main`; it refuses to run while the repository is private. Disable administrator
bypass under **Settings → Environments → showcase** if you want admins held too. From then on
the same approval jobs wait, and the summary names who approved.

After validation and scans, open the waiting run, choose **Review deployments**, select
`showcase`, and approve it. Only then does the publish/deploy job receive elevated permissions;
the reviewer remains in deployment history.

## Demo-only approval bypass

Manual runs expose `skip_approval=false`. Set it to `true` only for a demo that cannot pause;
the approval job is skipped and the downstream job records a warning. Push events cannot bypass.

GitHub provenance and SBOM attestations are also opt-in with `enable_attestations=false` because
GitHub does not offer them to user-owned private repositories. Enable the input only after the
repository or plan supports attestations; the SPDX SBOM artifact is produced either way.

Because the protected approval job itself does not access Azure, the existing
`repo:...:ref:refs/heads/main` federated credential remains sufficient; no environment-specific
Azure OIDC credential is required.

## Demo sequence

For the full exception demo, enable both finding exceptions and request publishing. Findings
are bypassed visibly, but `showcase` still blocks deployment unless `skip_approval=true`.

## Pinned Defender CLI update

The workflows checksum the downloaded Defender CLI. When Microsoft publishes a new binary, the
checksum mismatch intentionally fails closed. Review the new version, calculate its SHA-256, and
update `DEFENDER_CLI_SHA256` in the affected workflows before rerunning them.

