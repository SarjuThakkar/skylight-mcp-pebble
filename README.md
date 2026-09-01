# Skylight MCP server

Lets a [Pebble Index](https://repebble.com/index) ring add events to a
[Skylight](https://www.ourskylight.com/) family calendar by voice. Pebble's
cloud agent is the MCP client; this server does the HTTP work against
Skylight's unofficial API. Pebble never talks to Skylight directly, and
Skylight never sees your Pebble account.

Two calendar tools are exposed. `create_event` adds an event; it can auto-tag
a default family member profile and understands "me"/"myself" as that person,
or any other member by name. `list_events` reads the calendar back —
`list_events()` with no arguments answers "what's on today", `days` widens the
window and `who` narrows it to one person — and returns a spoken-style summary
rather than JSON.

Reading was deliberately left out of the original build (Pebble only needed to
write, and one tool kept the surface unambiguous). It was added once an
always-on Claude Code agent started sharing this server and needed to answer
"what's on my calendar today".

Transport: **Streamable HTTP**. Auth: a static bearer token in the
`Authorization` header (Pebble doesn't support OAuth login flows for custom
MCP servers, only a fixed header).

## Is this reusable for someone else's Pebble + Skylight?

Yes — nothing in the code is tied to a specific person. Every account-specific
value (Skylight login, frame id, timezone, which family member is the
default, the bearer token) comes from an environment variable, and family
member names are resolved live against *your* Skylight categories, not
hardcoded. Anyone with their own Skylight account, a Pebble Index, and a place
to host a small Python HTTP service can run their own copy. See
[Deploying](#deploying-to-railway) below — it's a handful of CLI commands,
not a manual code edit.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SKYLIGHT_EMAIL` | yes | Your `app.ourskylight.com` login email. |
| `SKYLIGHT_PASSWORD` | yes | Your `app.ourskylight.com` login password. |
| `SKYLIGHT_FRAME_ID` | yes | The number from `app.ourskylight.com/calendar/<id>` while logged in. |
| `MCP_BEARER_TOKEN` | yes | Static token Pebble sends as `Authorization: Bearer <token>`. Generate with `openssl rand -hex 32`. |
| `SKYLIGHT_TIMEZONE` | no | IANA timezone naive event times are interpreted in. Defaults to `America/Chicago`. This is also what the tool's docstring tells Pebble's agent, so it stays in sync automatically. |
| `SKYLIGHT_DEFAULT_MEMBER` | no | A Skylight family member's profile name (must match a category label on your calendar). Used when `who` is omitted, and what "me"/"myself"/"i" resolve to. Leave unset for no default tagging. |
| `PORT` | no | Set automatically by Railway/most hosts. Defaults to `8000` locally. |

## Local setup

```bash
python3 -m venv .venv && source .venv/bin/activate   # needs Python 3.10+
pip install -r requirements.txt

cp .env.example .env   # then fill in real values
export $(grep -v '^#' .env | xargs)   # or use your own env loader
export MCP_BEARER_TOKEN=$(openssl rand -hex 32)

python skylight_mcp_server.py
```

The server listens on `http://0.0.0.0:8000` (or `$PORT` if set), MCP
endpoint at `/mcp`, health check at `/healthz` (no auth required).

## Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

In the Inspector UI:

1. Transport: **Streamable HTTP**
2. URL: `http://localhost:8000/mcp`
3. Under Authentication, add header `Authorization: Bearer <your MCP_BEARER_TOKEN>`
4. Connect, then call `create_event` with a test title and check it landed
   on the right profile in the Skylight app.
5. Call `list_events` with no arguments — the event you just created should
   come back in the summary, tagged to the same profile.

## Deploying to Railway

### Option A: the `deploy.sh` helper

```bash
export SKYLIGHT_EMAIL=you@example.com
export SKYLIGHT_PASSWORD=...
export SKYLIGHT_FRAME_ID=1234567
export MCP_BEARER_TOKEN=$(openssl rand -hex 32)
# optional:
export SKYLIGHT_TIMEZONE=America/Chicago
export SKYLIGHT_DEFAULT_MEMBER=YourName

./deploy.sh
```

It installs the Railway CLI if missing, prompts you to log in (browser
OAuth — this part can't be scripted), creates the project on first run, sets
all the env vars, deploys, and prints the public URL. Re-run it any time
after editing `skylight_mcp_server.py` to push a new build — the project link
is stored in `~/.railway/config.json` keyed by this directory, not in the
repo, so nothing Railway-specific ends up in git.

### Option B: by hand

```bash
railway login                                  # browser OAuth
railway init --name skylight-mcp               # first time only
railway variable set SKYLIGHT_EMAIL=you@example.com --service skylight-mcp --skip-deploys
railway variable set SKYLIGHT_PASSWORD=... --service skylight-mcp --skip-deploys
railway variable set SKYLIGHT_FRAME_ID=1234567 --service skylight-mcp --skip-deploys
railway variable set MCP_BEARER_TOKEN=$(openssl rand -hex 32) --service skylight-mcp
railway up -c -y --service skylight-mcp        # builds the Dockerfile, deploys
railway domain --service skylight-mcp          # public HTTPS URL, real cert
```

**Redeploying later** (either you, after a code change, or anyone else who's
already run setup once) is just:

```bash
railway up -c -y --service skylight-mcp
```

That's the whole redeploy story — no config file beyond the `Dockerfile`
already in this repo, no CI pipeline. `railway logs --service skylight-mcp`
tails live logs, which is useful since `create_event`'s arguments are logged
on every call (see [Troubleshooting](#troubleshooting)).

Point Pebble's MCP client config at `https://<your-railway-domain>/mcp` with
the bearer token from setup.

## Configuring the Pebble app

In the Pebble app's MCP server settings:

- **Name**: anything, but **no spaces or special characters** — see
  [Troubleshooting](#troubleshooting). `SkylightCalendar` or
  `skylight-calendar` both work.
- **URL**: `https://<your-railway-domain>/mcp`
- **Transport**: **Streamable** (the dropdown is literally "SSE/Streamable" —
  pick Streamable, not SSE)
- **Authorization**: `Bearer <your MCP_BEARER_TOKEN>` — the full string,
  including the `Bearer ` prefix

Custom MCP tools only run in Pebble's **double-click** recording mode
(single-click uses Pebble's own built-in actions). Make sure this server is
assigned to whichever sandbox group your double-click uses.

## How family member tagging works

Family members aren't configured in this server at all — `create_event`
calls `GET /frames/{id}/categories` on your real Skylight account (cached in
memory per process) and matches the `who` argument against those labels,
case-insensitively. "me"/"myself"/"i" resolve to `SKYLIGHT_DEFAULT_MEMBER`.
If an exact match fails, it falls back to a fuzzy match (`difflib`) against
the same labels, since Pebble's speech-to-text can mangle less common names
(e.g. "Metree" or "May Tree" both still resolve to "Maitree" — verified
live). Names that still don't match anything don't block the event — it's
created without a profile tag, and the confirmation says so, so a mis-hearing
is visible instead of silently wrong.

## Example phrases to try

Each exercises a different part of the tool — after saying one (double-click
the ring), check Skylight for date/time, all-day vs. timed, and which
profile(s) got tagged:

- **"Add a dentist appointment tomorrow at 2pm."**
  Timed event, defaults to `SKYLIGHT_DEFAULT_MEMBER`'s profile, no location.
- **"Block off next Monday as a vacation day."**
  No time spoken → lands as an **all-day** event (auto-detected from the
  bare date — you don't need to say "all day" for this to work).
- **"Add a trip to Chicago from the 2nd to the 3rd of September."**
  Multi-day all-day event — spans both days inclusively.
- **"Add Maitree's haircut next Tuesday at 10am."**
  Explicit `who` — tags that person's profile instead of the default.
- **"Add family movie night Friday at 7pm for Maitree and me."**
  Multi-person tagging — lands tagged to both.
- **"Add a dentist appointment at Dr. Smith's office next Wednesday at 3pm."**
  Tests the `location` field getting captured.

## What's verified vs. assumed

The Skylight API is unofficial and reverse-engineered. This server's auth
flow and payload shapes were **live-tested against a real account on
2026-08-26/27** (see the module docstring in `skylight_mcp_server.py` for the
exact login steps). Notable findings that contradicted the initial
assumptions pulled from a Dec-2025 OpenAPI capture:

- The old `POST /api/sessions` (email/password → Basic auth) login is
  **retired** — it now returns 401 "This version of Skylight is no longer
  supported." The live flow is a 4-step OAuth2 authorization-code exchange
  (no PKCE required for this flow to succeed, though a PKCE variant also
  exists in the wild).
- `skylight-api-version: 2026-05-01` is required on every API call.
- `date_max` on `GET .../calendar_events` is an **exclusive** upper bound.
- **All-day events' `ends_at` is also exclusive** — a single-day all-day
  event needs `ends_at` at midnight of the *next* day (or, equivalently,
  equal to `starts_at`, which also works), and an N-day span needs `ends_at`
  padded one day past the last inclusive day. `create_event` handles this
  padding internally so its own `end` argument stays inclusive for callers.
- Family members are tagged via `category_ids` (an array) on the create
  payload; category ids come from `GET .../categories` and are cached per
  process.

Further findings from live-testing the **read** side on 2026-09-01, while
adding `list_events`:

- `date_min`/`date_max` match on each event's **UTC** date, not its local
  one. A 7pm Central event is stored at 00:00Z the next day and is returned
  only by the *following* day's window — so querying "today" unpadded
  silently drops the whole evening. `list_events` asks for a day either side
  and narrows to the local window itself.
- All-day events read back pinned to **UTC midnight** (`2026-09-01T00:00:00
  .000Z`) whatever offset they were written with — Skylight normalizes them
  to bare dates. Converting one to local time moves it a day earlier, so
  `list_events` takes all-day dates straight off the UTC timestamp and only
  converts timed events.
- Recurring events are **expanded server-side** into one row per occurrence,
  each with a composite `{master_id}-{epoch}` id, so no client-side RRULE
  expansion is needed. `rrule` is an *array* of iCalendar lines on write
  (`["RRULE:FREQ=WEEKLY;COUNT=4"]`); a bare string is a 422.
- The category relationship on an event is `category` (a single object) on a
  plain read, but becomes `categories` (an array) if `include=categories` is
  passed. Category records come back under `included` either way, so
  `list_events` resolves member names without a second request.

If Skylight changes its API again, these are the places most likely to
break: `_login()` (the OAuth steps) and the `calendar_events` payload shape
in `create_event`/`list_events`.

## Troubleshooting

**Pebble says "invalid tool call, action failed" and nothing lands on the
calendar.** Check `railway logs --service skylight-mcp` first — every
`create_event` call logs its raw arguments, and Skylight API failures are
caught and logged too. Two things this project already hit:

- **MCP server name has a space or special character in the Pebble app's
  config.** Confirmed on the
  [Pebble forum](https://forum.repebble.com/t/debugging-agent-messages-and-invalid-tool-call/1406):
  a space in the server's `Name` field makes the agent construct the wrong
  composite tool name and the call silently never reaches the server (you'll
  see `ListToolsRequest` in the logs but no `CallToolRequest`). Rename it to
  alphanumeric + hyphens only.
- **Optional tool arguments typed as nullable (`str | None`).** Some
  strict function-calling validators reject a JSON schema with `anyOf:
  [string, null]` before ever sending the request. This server uses plain
  `str = ""` (empty string = "not provided") instead, specifically to avoid
  that.

**A date/time didn't parse.** `create_event` catches this and returns a
descriptive error string (visible wherever Pebble surfaces tool results)
instead of crashing, naming exactly what it couldn't parse.

**An event landed at the wrong time (e.g. 2am).** Almost certainly a naive
vs. UTC mixup. `create_event`'s naive-time handling always assumes
`SKYLIGHT_TIMEZONE`, never UTC — if you're seeing this, check whether
Pebble sent a bare UTC time by mistake (check the logged raw `start` arg).

## Verifying the bearer check

```bash
# No token -> 401
curl -i https://<your-railway-domain>/healthz    # should be 200, no auth needed
curl -i https://<your-railway-domain>/mcp         # should be 401

# With token -> reaches the MCP layer
curl -i https://<your-railway-domain>/mcp \
  -H "Authorization: Bearer <your MCP_BEARER_TOKEN>" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2026-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
```
