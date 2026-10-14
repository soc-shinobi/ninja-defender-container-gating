# Layer 0: local pre-commit secret scan (skippable on purpose)

Install in EITHER demo repo to show the developer-side control that a developer
can bypass with `--no-verify`.

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.4
    hooks:
      - id: gitleaks
```

Setup:
```bash
pipx install pre-commit    # or: pip install pre-commit
pre-commit install
```

Demo beat (Layer 0):
```bash
echo 'ACR_PASSWORD=SuperSecretValue123!' >> config/app.env
git add config/app.env
git commit -m "add config"        # gitleaks blocks it
git commit -m "add config" --no-verify   # developer bypasses. Box 0 stays dark.
git push                          # GitHub push protection blocks at the org (Box 1)
```
