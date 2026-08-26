"""
Skylight MCP server for Pebble Index.

Speaks Streamable HTTP, guards itself with a static bearer token, and exposes
calendar tools that the Pebble cloud agent can call.

  pip install fastmcp httpx uvicorn
  export SKYLIGHT_EMAIL=you@example.com
  export SKYLIGHT_PASSWORD=...
  export SKYLIGHT_FRAME_ID=3648496        # from app.ourskylight.com/calendar/<id>
  export MCP_BEARER_TOKEN=$(openssl rand -hex 32)
  python skylight_mcp_server.py

WARNING: unofficial reverse-engineered API. It can change without notice, and
this process holds your Skylight password. Host it somewhere you control.

Auth, live-verified 2026-08-26 against a real account:
  Skylight retired the old `POST /api/sessions` (email/password -> Basic
  token) login -- it now 401s with "This version of Skylight is no longer
  supported." The live flow is a 4-step OAuth2 authorization-code exchange
  (no PKCE needed; a PKCE variant also exists in the wild but wasn't required
  here):
    1. GET  /auth/session/new      -> authenticity_token (CSRF) + session cookie
    2. POST /auth/session          -> credentials, redeems the cookie
    3. GET  /oauth/authorize       -> redirects to redirect_uri?code=...
    4. POST /oauth/token           -> code -> {access_token, refresh_token}
  The resulting access_token is sent as `Authorization: Bearer <token>` on
  every API call, alongside `skylight-api-version: 2026-05-01` (confirmed
  live; the API 422s some endpoints without it). On a 401, re-run the login
  and retry once -- Skylight rotates tokens on logout/expiry.
"""

import base64
import difflib
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("skylight_mcp")

import httpx
from fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

BASE = os.environ.get("SKYLIGHT_URL", "https://app.ourskylight.com")
API = f"{BASE}/api"
WEB = "https://ourskylight.com"
EMAIL = os.environ["SKYLIGHT_EMAIL"]
PASSWORD = os.environ["SKYLIGHT_PASSWORD"]
FRAME_ID = os.environ["SKYLIGHT_FRAME_ID"]
BEARER = os.environ["MCP_BEARER_TOKEN"]

# The events calendar is always interpreted in this zone unless the caller's
# ISO string carries its own UTC offset.
LOCAL_TZ = ZoneInfo(os.environ.get("SKYLIGHT_TIMEZONE", "America/Chicago"))

# Family member profile (a Skylight category label) new events are tagged to
# when `who` is omitted, and what "me"/"myself"/"i" resolve to. Optional --
# if unset, events created without an explicit `who` get no profile tag.
DEFAULT_MEMBER = os.environ.get("SKYLIGHT_DEFAULT_MEMBER", "").strip()

# skylight-mobile's OAuth2 client id + redirect. Matching the web app; some
# endpoints 422 without the api-version header.
CLIENT_ID = "skylight-mobile"
SCOPE = "everything"
REDIRECT_URI = f"{WEB}/welcome"
API_VERSION = "2026-05-01"
USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"

_AUTHENTICITY_TOKEN_RE = re.compile(
    r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']'
)
_DATE_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _is_date_only(value: str) -> bool:
    return bool(_DATE_ONLY_RE.match(value.strip()))

_access_token: str | None = None


class SkylightError(RuntimeError):
    """Raised for login failures and non-2xx Skylight API responses."""


async def _login() -> str:
    """Run the 4-step OAuth2 authorization-code exchange, return an access token.

    Never logs or echoes the password. Cookies must persist across all 4
    requests, so this uses a single client for the whole flow.
    """
    async with httpx.AsyncClient(base_url=BASE, timeout=20, follow_redirects=False) as client:
        # Step 1: CSRF token + session cookie.
        r = await client.get("/auth/session/new", headers={"User-Agent": USER_AGENT})
        match = _AUTHENTICITY_TOKEN_RE.search(r.text)
        if not match:
            raise SkylightError(
                "Skylight login step 1: no authenticity_token in /auth/session/new "
                "-- the login page markup may have changed."
            )
        authenticity_token = match.group(1)

        # Step 2: submit credentials.
        r = await client.post(
            "/auth/session",
            data={"authenticity_token": authenticity_token, "email": EMAIL, "password": PASSWORD},
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": BASE,
                "Referer": f"{BASE}/auth/session/new",
                "User-Agent": USER_AGENT,
            },
        )
        location = r.headers.get("location", "")
        if r.status_code not in (301, 302, 303) or "/auth/session/new" in location:
            raise SkylightError(
                "Skylight login step 2 failed -- check SKYLIGHT_EMAIL/SKYLIGHT_PASSWORD "
                "(or the account may be temporarily rate-limited)."
            )

        # Step 3: exchange the session for an authorization code. Follow
        # redirects manually, scanning each Location for ?code=.
        authorize_url = (
            f"{BASE}/oauth/authorize?client_id={CLIENT_ID}&response_type=code"
            f"&scope={SCOPE}&redirect_uri={httpx.QueryParams({'u': REDIRECT_URI})['u']}"
        )
        code = None
        next_url = authorize_url
        for _ in range(5):
            if next_url is None:
                break
            r = await client.get(next_url, headers={"User-Agent": USER_AGENT})
            loc = r.headers.get("location", "")
            code = httpx.URL(loc).params.get("code") if loc else None
            if code:
                break
            next_url = loc or None
        if not code:
            raise SkylightError("Skylight login step 3: no authorization code from /oauth/authorize.")

        # Step 4: exchange the code for an access token.
        r = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "scope": SCOPE,
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "skylight_api_client_device_fingerprint": str(uuid.uuid4()),
                "skylight_api_client_device_platform": "web",
                "skylight_api_client_device_name": "unknown",
                "skylight_api_client_device_os_version": "unknown",
                "skylight_api_client_device_app_version": "unknown",
                "skylight_api_client_device_hardware": "Macintosh",
                "source": "js-mobile",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        )
        if r.status_code != 200:
            raise SkylightError(f"Skylight login step 4 failed ({r.status_code}).")
        body = r.json()
        token = body.get("access_token")
        if not token:
            raise SkylightError("Skylight login step 4: no access_token in the response.")
        return token


async def _get_token() -> str:
    global _access_token
    if _access_token is None:
        _access_token = await _login()
    return _access_token


async def _request(method: str, path: str, **kw) -> dict:
    """Authenticated request against the Skylight API. Retries once on 401."""
    global _access_token
    token = await _get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "skylight-api-version": API_VERSION,
    }
    async with httpx.AsyncClient(base_url=API, timeout=20) as client:
        r = await client.request(method, path, headers=headers, **kw)
        if r.status_code == 401:
            _access_token = None
            headers["Authorization"] = f"Bearer {await _get_token()}"
            r = await client.request(method, path, headers=headers, **kw)
        if r.status_code >= 400:
            raise SkylightError(f"{method} {path} failed ({r.status_code}): {r.text[:300]}")
        return r.json() if r.content else {}


def _parse_local(value: str) -> datetime:
    """Parse an ISO 8601 date/datetime. Naive values are local to LOCAL_TZ."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=LOCAL_TZ)
    return dt


def _to_utc_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


_category_cache: dict[str, str] | None = None


async def _category_map() -> dict[str, str]:
    """Family-member/category label (lowercased) -> category id, cached for the process."""
    global _category_cache
    if _category_cache is None:
        data = await _request("GET", f"/frames/{FRAME_ID}/categories")
        _category_cache = {
            item["attributes"]["label"].lower(): item["id"]
            for item in data.get("data", [])
            if item.get("attributes", {}).get("label")
        }
    return _category_cache


_SELF_ALIASES = {"me", "myself", "i"}


async def _resolve_who(who: str) -> tuple[list[str], list[str]]:
    """Split a free-text name list and match each against known categories.

    "me"/"myself"/"i" resolve to SKYLIGHT_DEFAULT_MEMBER (the server owner),
    if set. An exact case-insensitive match is tried first; if that fails,
    falls back to a fuzzy match against known category labels, since
    Pebble's speech-to-text can mangle less common names (e.g. "Metree" ->
    "Maitree"). Returns (matched_category_ids, unmatched_names).
    """
    names = [n.strip() for n in re.split(r",|&|\band\b", who, flags=re.IGNORECASE) if n.strip()]
    mapping = await _category_map()
    matched, unmatched = [], []
    for name in names:
        if name.lower() in _SELF_ALIASES and DEFAULT_MEMBER:
            key = DEFAULT_MEMBER.lower()
        else:
            key = name.lower()
        cat_id = mapping.get(key)
        if not cat_id:
            close = difflib.get_close_matches(key, mapping.keys(), n=1, cutoff=0.6)
            if close:
                logger.info("create_event: fuzzy-matched who %r -> %r", name, close[0])
                cat_id = mapping[close[0]]
        if cat_id:
            matched.append(cat_id)
        else:
            unmatched.append(name)
    return matched, unmatched


class BearerAuth(BaseHTTPMiddleware):
    """Static bearer check. Pebble sends whatever header you configure."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/healthz":
            return await call_next(request)
        sent = request.headers.get("authorization", "")
        if sent != f"Bearer {BEARER}":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


mcp = FastMCP("skylight")


async def create_event(
    title: str,
    start: str,
    end: str = "",
    location: str = "",
    all_day: bool = False,
    who: str = "",
) -> str:
    """Add an event to the family calendar.

    Args:
        title: What the event is called, e.g. "Dentist appointment".
        start: When it begins. Either a naive local time in
            {tz}, format "YYYY-MM-DDTHH:MM" (e.g.
            "2026-09-02T14:00" for 2pm on Sep 2), or a full ISO 8601
            string with a UTC offset (e.g. "2026-09-02T14:00:00-05:00").
            A naive time is ALWAYS read as {tz} local time,
            never UTC -- do not pass a bare UTC time here.
            Pass just a date, "YYYY-MM-DD" (no time), to make it an
            all-day event -- this happens automatically, you do not
            also need to set all_day in that case.
        end: When it ends, same format rules as `start`. Leave as an
            empty string if unknown -- defaults to one hour after
            `start` for a timed event, or the same day as `start` for
            an all-day event. For a multi-day all-day event (e.g. a
            trip), pass the last day as a plain date, e.g. "2026-09-05".
        location: Place name, e.g. "Dr. Smith's office". Leave as an
            empty string if there is no specific location.
        all_day: Force an all-day event even when `start` includes a
            time (the time is then ignored). You usually don't need to
            set this explicitly -- omitting the time on `start` already
            makes the event all-day.
        who: The family member(s) this event is for. Leave as an empty
            string to use the default profile (if one is configured --
            most events created this way are for the same person, so
            you don't need to say a name for that case). "me"/"myself"
            also means the default profile. For more than one person,
            separate names with "and" or a comma, e.g. "Maitree and
            me". Matched case-insensitively against the family member
            profiles on this calendar. If a name doesn't match anyone,
            the event is still created, just without that person's
            profile tag (mentioned in the confirmation so it can be
            corrected).

    Returns a confirmation string naming the event, when it was added,
    and who it's tied to.
    """
    logger.info(
        "create_event args: title=%r start=%r end=%r location=%r all_day=%r who=%r",
        title, start, end, location, all_day, who,
    )

    try:
        is_all_day = all_day or _is_date_only(start)
        start_dt = _parse_local(start)
        if is_all_day:
            # Skylight's ends_at is an EXCLUSIVE boundary for all-day events,
            # same as date_max on the read side (verified live 2026-08-27:
            # a literal start=9/2, end=9/3 all-day event only covered 9/2).
            # Normalize to local midnight and pad the last day by one so a
            # caller's `end` stays inclusive.
            start_dt = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            last_day_dt = _parse_local(end) if end else start_dt
            last_day_midnight = last_day_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            end_dt = last_day_midnight + timedelta(days=1)
        else:
            end_dt = _parse_local(end) if end else start_dt + timedelta(hours=1)
    except ValueError as exc:
        logger.warning("create_event: bad date/time %r / %r: %s", start, end, exc)
        return (
            f"Could not understand the date/time \"{start}\"" + (f" or \"{end}\"" if end else "")
            + ". Expected something like \"2026-09-02T14:00\" for 2pm on Sep 2, or a plain date"
            f" \"2026-09-02\" for all-day. Error: {exc}"
        )

    payload = {
        "summary": title,
        "starts_at": _to_utc_z(start_dt),
        "ends_at": _to_utc_z(end_dt),
        "all_day": is_all_day,
        "timezone": str(LOCAL_TZ),
        "kind": "standard",
    }
    if location:
        payload["location"] = location

    effective_who = who if who else DEFAULT_MEMBER
    matched_ids, unmatched = await _resolve_who(effective_who) if effective_who else ([], [])
    if matched_ids:
        payload["category_ids"] = matched_ids

    try:
        await _request("POST", f"/frames/{FRAME_ID}/calendar_events", json=payload)
    except SkylightError as exc:
        logger.error("create_event: Skylight API call failed: %s", exc)
        return f"Failed to add '{title}' to the calendar -- Skylight rejected the request: {exc}"

    if is_all_day:
        last_inclusive_day = (end_dt - timedelta(days=1)).date()
        if last_inclusive_day > start_dt.date():
            when_str = f"as an all-day event from {start_dt.date().isoformat()} to {last_inclusive_day.isoformat()}"
        else:
            when_str = f"as an all-day event on {start_dt.date().isoformat()}"
    else:
        local_start = start_dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %I:%M %p").replace(" 0", " ")
        when_str = f"starting {local_start} ({LOCAL_TZ})"

    result = f"Added '{title}' {when_str}."
    if matched_ids and not unmatched:
        result += f" Tagged to {effective_who}."
    elif unmatched:
        result += f" Could not match family member(s) {', '.join(unmatched)} -- created without a profile tag."
    return result


# The docstring above is what Pebble's agent parses argument formats from, so
# the timezone it names has to match LOCAL_TZ (configurable via
# SKYLIGHT_TIMEZONE) rather than being hardcoded for one deployment.
create_event.__doc__ = create_event.__doc__.format(tz=str(LOCAL_TZ))
mcp.tool()(create_event)


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = mcp.http_app(path="/mcp")
app.add_middleware(BearerAuth)
app.router.routes.insert(0, __import__("starlette.routing", fromlist=["Route"]).Route("/healthz", healthz))

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
