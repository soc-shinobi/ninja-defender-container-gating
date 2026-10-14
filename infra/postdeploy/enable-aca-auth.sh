#!/usr/bin/env bash
# Put Microsoft Entra sign-in in front of the control panel (Container Apps built-in auth,
# "EasyAuth"), SCOPED TO ONE NAMED USER - not the whole tenant.
#
#   PANEL_ENTRA_USER=<user@tenant> make auth
#
# If no user is given this exits cleanly: the deployment then runs in basic-auth mode with a
# random password instead. Either way the panel is never reachable anonymously.
#
# What this creates:
#   1. an Entra app registration with the EasyAuth callback as its redirect URI
#   2. ID token issuance enabled (required by EasyAuth) + a service principal
#   3. a client secret, stored as a Container App SECRET (never printed, never in git)
#   4. the Microsoft identity provider on the app, with unauthenticated browser
#      requests redirected to the Entra sign-in page
#
# After this, every request must carry a signed-in Entra user. The panel reads that user
# from X-MS-CLIENT-PRINCIPAL-NAME and passes it to Defender for AI as the end-user context,
# so AI alerts name the human, not the app's managed identity.
#
# Verified against Microsoft Learn 2026-09-19 (azure/container-apps/authentication-entra).
set -euo pipefail

# needs the `containerapp` CLI extension; `make deploy` installs it (scripts/az-prereqs.sh).
# run standalone on a fresh machine, let az fetch it instead of prompting.
az config set extension.use_dynamic_install=yes_without_prompt -o none 2>/dev/null || true

RG="${RG:-rg-defdemo}"
APP="${APP:-${NAME_PREFIX:-defdemo}-app}"
DISPLAY_NAME="${AUTH_APP_NAME:-$APP-panel-auth}"
SECRET_NAME="microsoft-provider-authentication-secret"
USER_INPUT="${PANEL_ENTRA_USER:-${1:-}}"

if [[ -z "$USER_INPUT" ]]; then
  cat <<'EOT'
No PANEL_ENTRA_USER given, so nothing to do here.

The panel is already protected: with no Entra user the deployment falls back to HTTP Basic
with a random password that `make deploy` generated, stored as a Container App secret. It is
never left open.

To switch to Entra sign-in scoped to one user:
    PANEL_ENTRA_USER=<user@tenant> make deploy     # drops basic auth from the app
    PANEL_ENTRA_USER=<user@tenant> make auth       # registers + assigns ONLY that user
EOT
  exit 0
fi

c(){ printf '\033[%sm%s\033[0m\n' "$1" "$2"; }

FQDN="$(az containerapp show -g "$RG" -n "$APP" --query properties.configuration.ingress.fqdn -o tsv)"
TENANT_ID="$(az account show --query tenantId -o tsv)"
CALLBACK="https://${FQDN}/.auth/login/aad/callback"
c '1;36' "▶ app=$APP  fqdn=$FQDN"
c '1;36' "▶ callback=$CALLBACK"

# 1. app registration (idempotent: reuse one with the same display name)
APP_ID="$(az ad app list --display-name "$DISPLAY_NAME" --query "[0].appId" -o tsv 2>/dev/null || true)"
if [[ -z "$APP_ID" || "$APP_ID" == "None" ]]; then
  APP_ID="$(az ad app create --display-name "$DISPLAY_NAME" --sign-in-audience AzureADMyOrg \
            --query appId -o tsv)"
  c '1;32' "✔ created app registration $APP_ID"
else
  c '1;33' "ℹ reusing existing app registration $APP_ID"
fi

# 2. EasyAuth needs ID tokens and the callback URI; service principal must exist
az ad app update --id "$APP_ID" --enable-id-token-issuance true --web-redirect-uris "$CALLBACK"
az ad sp create --id "$APP_ID" -o none 2>/dev/null || true
c '1;32' "✔ id-token issuance on, redirect URI set, service principal present"

# 3. client secret -> Container App secret (not echoed, not committed)
CLIENT_SECRET="$(az ad app credential reset --id "$APP_ID" --display-name "$APP-easyauth" \
                  --query password -o tsv)"
az containerapp secret set -g "$RG" -n "$APP" \
  --secrets "$SECRET_NAME=$CLIENT_SECRET" -o none
c '1;32' "✔ client secret stored as Container App secret '$SECRET_NAME'"

# 4. identity provider + require authentication
az containerapp auth microsoft update -g "$RG" -n "$APP" \
  --client-id "$APP_ID" \
  --client-secret-name "$SECRET_NAME" \
  --tenant-id "$TENANT_ID" \
  --issuer "https://login.microsoftonline.com/$TENANT_ID/v2.0" \
  --yes -o none
# --action and --unauthenticated-client-action are ALIASES of the same parameter; pass one.
# Allowed values: RedirectToLoginPage | AllowAnonymous | Return401 | Return403.
# RedirectToLoginPage = browser users get bounced to the Entra sign-in page, which is what
# you want for a UI. (Return401 would be right for an API.)
az containerapp auth update -g "$RG" -n "$APP" \
  --enabled true \
  --redirect-provider AzureActiveDirectory \
  --unauthenticated-client-action RedirectToLoginPage -o none
c '1;32' "✔ Entra sign-in required on https://$FQDN"

# 5. SCOPE IT: require assignment, then assign only the named user. Without this every
#    user in the tenant could sign in, which is not "scoped to a user".
SP_ID="$(az ad sp show --id "$APP_ID" --query id -o tsv)"
USER_ID="$(az ad user show --id "$USER_INPUT" --query id -o tsv)"
az rest --method PATCH --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID" \
  --headers "Content-Type=application/json" \
  --body '{"appRoleAssignmentRequired":true}' -o none
c '1;32' "✔ assignment required: tenant-wide sign-in is now OFF"

if az rest --method POST \
     --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo" \
     --headers "Content-Type=application/json" \
     --body "{\"principalId\":\"$USER_ID\",\"resourceId\":\"$SP_ID\",\"appRoleId\":\"00000000-0000-0000-0000-000000000000\"}" \
     -o none 2>/dev/null; then
  c '1;32' "✔ assigned $USER_INPUT ($USER_ID) - only this user can sign in"
else
  c '1;33' "! assignment already exists for $USER_INPUT (or insufficient Graph permission)"
fi

cat <<EOF

SCOPED TO: $USER_INPUT
  Anyone else in the tenant is refused at sign-in. Add more people with:
    az rest --method POST \\
      --uri https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignedTo \\
      --headers "Content-Type=application/json" \\
      --body '{"principalId":"<objectId>","resourceId":"$SP_ID","appRoleId":"00000000-0000-0000-0000-000000000000"}'

VERIFY:
  curl -s -o /dev/null -w '%{http_code}\\n' https://$FQDN/      # expect 302 to login
  then open https://$FQDN/ in a browser and sign in.

NOTE: /healthz is behind auth too. If you want an unauthenticated probe, switch the action
to AllowAnonymous and enforce in app code instead.
EOF
