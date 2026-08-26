#!/usr/bin/env bash
# One-time setup + redeploy helper for Railway.
#
# First run: creates a Railway project, sets your env vars, deploys, and
# prints the public URL. Re-run any time after editing
# skylight_mcp_server.py to push a new build (env vars are left as-is on
# repeat runs unless you change them below).
#
# Usage:
#   export SKYLIGHT_EMAIL=you@example.com
#   export SKYLIGHT_PASSWORD=...
#   export SKYLIGHT_FRAME_ID=1234567
#   export MCP_BEARER_TOKEN=$(openssl rand -hex 32)
#   # optional:
#   export SKYLIGHT_TIMEZONE=America/Chicago
#   export SKYLIGHT_DEFAULT_MEMBER=YourName
#   ./deploy.sh
set -euo pipefail

PROJECT_NAME="${RAILWAY_PROJECT_NAME:-skylight-mcp}"

: "${SKYLIGHT_EMAIL:?Set SKYLIGHT_EMAIL first}"
: "${SKYLIGHT_PASSWORD:?Set SKYLIGHT_PASSWORD first}"
: "${SKYLIGHT_FRAME_ID:?Set SKYLIGHT_FRAME_ID first}"
: "${MCP_BEARER_TOKEN:?Set MCP_BEARER_TOKEN first, e.g. export MCP_BEARER_TOKEN=\$(openssl rand -hex 32)}"

if ! command -v railway >/dev/null 2>&1; then
  echo "Installing Railway CLI..."
  curl -fsSL https://railway.app/install.sh | sh
  # shellcheck disable=SC1091
  source "$HOME/.railway/env"
fi

railway whoami >/dev/null 2>&1 || railway login

# `railway status` only succeeds if this directory is already linked to a
# project (the link lives in ~/.railway/config.json, keyed by this path --
# nothing project-local, nothing that ends up in git).
if ! railway status >/dev/null 2>&1; then
  railway init --name "$PROJECT_NAME" --json
fi

set_var() {
  railway variable set "$1=$2" --service "$PROJECT_NAME" --skip-deploys --json >/dev/null
}
set_var SKYLIGHT_EMAIL "$SKYLIGHT_EMAIL"
set_var SKYLIGHT_PASSWORD "$SKYLIGHT_PASSWORD"
set_var SKYLIGHT_FRAME_ID "$SKYLIGHT_FRAME_ID"
[ -n "${SKYLIGHT_TIMEZONE:-}" ] && set_var SKYLIGHT_TIMEZONE "$SKYLIGHT_TIMEZONE"
[ -n "${SKYLIGHT_DEFAULT_MEMBER:-}" ] && set_var SKYLIGHT_DEFAULT_MEMBER "$SKYLIGHT_DEFAULT_MEMBER"
railway variable set "MCP_BEARER_TOKEN=$MCP_BEARER_TOKEN" --service "$PROJECT_NAME" --json >/dev/null

railway up -c -y --service "$PROJECT_NAME"
railway domain --service "$PROJECT_NAME" || true

echo
echo "Done. If this is the first run, grab the URL above, add /mcp to the"
echo "end of it, and use that + your MCP_BEARER_TOKEN in the Pebble app."
