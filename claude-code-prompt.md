# Prompt for Claude Code

Build and deploy an MCP server that lets my Pebble Index ring add events to my
Skylight family calendar by voice.

## Architecture

Pebble's cloud agent is the MCP client. It connects to my server over the public
internet, reads my tool schemas, and decides which tool to call. My server does
the actual HTTP work against Skylight. Pebble never talks to Skylight directly.

## Hard constraints

- **Transport: Streamable HTTP.** Pebble supports SSE and Streamable HTTP; prefer
  Streamable HTTP since the ecosystem is moving off SSE.
- **Auth: a static bearer token in the `Authorization` header.** Pebble does not
  support OAuth. Reject anything else with a 401. Generate the token with
  `openssl rand -hex 32` and keep it in an env var.
- **Public HTTPS required.** No self-signed certs.
- Secrets come from env vars only: `SKYLIGHT_EMAIL`, `SKYLIGHT_PASSWORD`,
  `SKYLIGHT_FRAME_ID`, `MCP_BEARER_TOKEN`. Never commit them. Add a
  `.env.example` with placeholder values and a `.gitignore` that excludes `.env`.

## The Skylight API

It is unofficial and reverse-engineered from network traffic. Do **not** invent
endpoints or field names. Before writing any request code, read these and confirm
the real shapes:

- `github.com/TheEagleByte/skylight-api` — OpenAPI spec generated from HAR captures
- `github.com/chrischall/skylight-mcp` — actively maintained, most complete
- `github.com/lancereinsmith/claude-skylight-plugin` — Python, includes a reusable client

What I already know, to be verified rather than trusted:

- Base URL is `https://app.ourskylight.com`
- Login returns `data.id` and `data.attributes.token`; combine as
  `{user_id}:{user_token}`, base64-encode, send as `Authorization: Basic <b64>`
- Every request needs a `skylight-api-version: 2026-05-01` header, or some
  endpoints 422 with a version complaint
- Events live under `/api/frames/{frame_id}/calendar_events`; the GET takes
  `date_min` and `date_max` as `YYYY-MM-DD`
- Responses are JSON:API shaped (`data`, `included`, `relationships`)
- Tokens rotate on logout, so cache the auth header but retry once on a 401

## Build order

1. `list_events(date_min, date_max)` first. It is read-only, so a wrong guess
   about the API costs me nothing. Do not move on until it returns my real
   calendar data.
2. `create_event(title, start, end, location, all_day)` only after step 1 works.

## Tool descriptions matter more than usual

The docstrings are the only thing Pebble's agent ever sees about these tools. It
is parsing spoken fragments like "dentist tuesday at 2" into arguments with no
chance for me to correct it. So:

- State the exact expected format for every argument, with an example.
- Be explicit about timezones. I am in America/Chicago. Decide whether `start`
  takes an ISO 8601 string with offset or a naive local time, document that
  choice unambiguously, and handle it consistently. Events landing at 2am
  because of a UTC mixup is the specific failure I want to avoid.
- Say what happens to omitted optional arguments.

## Deliverables

- The server, in Python with FastMCP (or argue for something better)
- A `/healthz` endpoint that skips auth
- A README with local run instructions and how to test with MCP Inspector
- Deployment to Railway: Dockerfile or nixpacks config, env vars documented
- The final MCP URL and a curl command proving the bearer check works
  (401 without the token, 200 with it)

## How I want you to work

Confirm each layer before building on it: auth works, then read works, then write
works. Show me the actual response bodies from Skylight as you go — I would
rather see one real payload than a plausible guess. If the reference repos
disagree with each other, tell me and ask rather than picking one silently.
