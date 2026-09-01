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
  As of 2026-09-01 step 3 REQUIRES PKCE: without code_challenge +
  code_challenge_method it returns `400 Code challenge is required.`, and
  the matching code_verifier must be sent at step 4. This was optional when
  the flow was first mapped, which is the standing hazard of an unofficial
  API -- it changed with no notice.

  The resulting access_token is sent as `Authorization: Bearer <token>` on
  every API call, alongside `skylight-api-version: 2026-05-01` (confirmed
  live; the API 422s some endpoints without it). On a 401, re-run the login
  and retry once -- Skylight rotates tokens on logout/expiry.
"""

import base64
import difflib
import hashlib
import secrets
import logging
import os
import re
import time
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
_refresh_token: str | None = None
# Unix seconds. Skylight issues 24h access tokens alongside a refresh token.
_token_expires_at: float = 0.0
# Renew a little early rather than discovering expiry as a failed API call.
_TOKEN_MARGIN = 300


class SkylightError(RuntimeError):
    """Raised for login failures and non-2xx Skylight API responses."""


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256.

    Skylight began rejecting the plain authorization-code flow with
    `400 Code challenge is required.` -- PKCE used to be optional here and
    is now mandatory. Both values are per-login and never reused.
    """
    verifier = secrets.token_urlsafe(64)[:96]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


async def _login() -> str:
    """Run the 4-step OAuth2 authorization-code exchange, return an access token.

    Never logs or echoes the password. Cookies must persist across all 4
    requests, so this uses a single client for the whole flow.
    """
    verifier, challenge = _pkce_pair()
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
        authorize_url = f"{BASE}/oauth/authorize?" + str(
            httpx.QueryParams(
                {
                    "client_id": CLIENT_ID,
                    "response_type": "code",
                    "scope": SCOPE,
                    "redirect_uri": REDIRECT_URI,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
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
                # Proves this is the same client that started the flow.
                "code_verifier": verifier,
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
        _remember(body)
        return token


def _remember(body: dict) -> None:
    """Record the token, its refresh token, and when it expires."""
    global _access_token, _refresh_token, _token_expires_at
    _access_token = body.get("access_token")
    _refresh_token = body.get("refresh_token") or _refresh_token
    _token_expires_at = time.time() + float(body.get("expires_in", 86400))


async def _refresh() -> str | None:
    """Renew with the refresh token. Returns None if that isn't possible.

    Preferred over a full re-login: it skips the password and the 4-step
    authorization dance entirely -- and that dance is the fragile part, as
    PKCE becoming mandatory demonstrated by breaking every login at once.
    """
    if not _refresh_token:
        return None
    async with httpx.AsyncClient(base_url=BASE, timeout=20) as client:
        r = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": _refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
        )
    if r.status_code != 200:
        logger.info("refresh token rejected (%s), falling back to a full login",
                    r.status_code)
        return None
    body = r.json()
    if not body.get("access_token"):
        return None
    _remember(body)
    logger.info("renewed the Skylight token without re-sending the password")
    return _access_token


async def _get_token() -> str:
    """A valid access token, renewed as cheaply as possible."""
    global _access_token
    if _access_token and time.time() < _token_expires_at - _TOKEN_MARGIN:
        return _access_token
    if _refresh_token:
        renewed = await _refresh()
        if renewed:
            return renewed
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
            # Force renewal on the next call; the refresh token gets first
            # refusal, and a full login only if that is rejected too.
            _access_token = None
            globals()["_token_expires_at"] = 0.0
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


_SELF_ALIASES = {"me", "myself", "i", "my", "mine", "for me", "my own"}

# Words meaning "everyone on the frame". Resolved to every family member, so
# "check off our workout" or "did us both" hits each person's copy.
_EVERYONE_ALIASES = {
    "us", "we", "both", "everyone", "everybody", "all", "all of us",
    "both of us", "the family", "family", "our", "ours", "each of us",
}


async def _resolve_who(who: str) -> tuple[list[str], list[str]]:
    """Split a free-text name list and match each against known categories.

    "me"/"myself"/"i" resolve to SKYLIGHT_DEFAULT_MEMBER (the server owner),
    if set. An exact case-insensitive match is tried first; if that fails,
    falls back to a fuzzy match against known category labels, since
    Pebble's speech-to-text can mangle less common names (e.g. "Metree" ->
    "Maitree"). Returns (matched_category_ids, unmatched_names).
    """
    mapping = await _category_map()

    # "us"/"we"/"both" means the whole household, not a name to look up.
    if re.sub(r"[^a-z ]", "", who.lower()).strip() in _EVERYONE_ALIASES:
        return list(mapping.values()), []

    names = [n.strip() for n in re.split(r",|&|\band\b", who, flags=re.IGNORECASE) if n.strip()]
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


# ---------------------------------------------------------------------------
# Lists, chores, rewards and meals
#
# Endpoint shapes below were confirmed against a real frame. Three of them are
# not guessable and cost real time to find:
#
#   * `meals` is a namespace, not a collection -- everything hangs off
#     /meals/recipes, /meals/sittings. A flat /meals is a 404.
#   * Chores are date-ranged like events; a bare GET is 422 "after can't be
#     blank".
#   * List items live under their parent list as `list_items`, not `items`.
# ---------------------------------------------------------------------------

def _flat(item: dict) -> dict:
    """JSON:API record -> plain dict of attributes plus its id."""
    out = dict(item.get("attributes") or {})
    out["id"] = item.get("id")
    return out


def _pick(spoken: str, options: dict[str, str], what: str) -> str:
    """Match spoken text against {label: id}, fuzzily. Raises if no match."""
    key = re.sub(r"^(the|my|our)\s+", "", spoken.lower().strip())
    if key in options:
        return options[key]
    close = difflib.get_close_matches(key, options.keys(), n=1, cutoff=0.6)
    if close:
        logger.info("fuzzy-matched %s %r -> %r", what, spoken, close[0])
        return options[close[0]]
    raise SkylightError(
        f"I don't have a {what} called '{spoken.strip()}'. "
        f"There's: {', '.join(sorted(options))}."
    )


async def _lists() -> list[dict]:
    data = await _request("GET", f"/frames/{FRAME_ID}/lists")
    return [_flat(i) for i in data.get("data", [])]


async def _resolve_list(name: str) -> dict:
    """Pick a list by spoken name.

    With no name, prefer the grocery list -- "add milk" almost always means
    the shopping list, and the frame flags exactly one as the default.
    """
    lists = await _lists()
    if not lists:
        raise SkylightError("There aren't any lists on the frame yet.")
    if not name.strip():
        for lst in lists:
            if lst.get("default_grocery_list"):
                return lst
        return lists[0]
    by_label = {l["label"].lower(): l["id"] for l in lists if l.get("label")}
    chosen = _pick(name, by_label, "list")
    return next(l for l in lists if l["id"] == chosen)


@mcp.tool
async def list_lists() -> str:
    """List the household shopping and to-do lists on the Skylight frame.

    HOUSEHOLD LISTS ONLY -- groceries, errands, chores, ideas. Books are not
    here: a reading list or book list lives on Goodreads, so use the Goodreads
    tools for those.

    Use this when the user asks what lists exist, or before adding to one if
    you're unsure of the exact name.
    """
    logger.info("list_lists: called")
    try:
        lists = await _lists()
    except SkylightError as err:
        return str(err)
    if not lists:
        return "There aren't any lists on the frame yet."
    parts = []
    for lst in lists:
        label = lst.get("label", "untitled")
        parts.append(f"{label} (grocery)" if lst.get("default_grocery_list") else label)
    return "Lists: " + ", ".join(parts) + "."


@mcp.tool
async def show_list(name: str = "") -> str:
    """Read back what's on a household list.

    HOUSEHOLD LISTS ONLY. For "what am I reading" or a to-read list, use the
    Goodreads tools instead.

    Args:
        name: Which list, as the user said it. Leave empty for the grocery list.
    """
    logger.info("show_list: name=%r", name)
    try:
        lst = await _resolve_list(name)
        data = await _request(
            "GET", f"/frames/{FRAME_ID}/lists/{lst['id']}/list_items"
        )
    except SkylightError as err:
        return str(err)
    items = [_flat(i) for i in data.get("data", [])]
    open_items = [i["label"] for i in items if i.get("status") != "complete" and i.get("label")]
    if not open_items:
        return f"The {lst.get('label')} is empty."
    return (
        f"{lst.get('label')} ({len(open_items)}): " + ", ".join(open_items) + "."
    )


@mcp.tool
async def add_to_list(items: str, name: str = "") -> str:
    """Add one or more items to a household list.

    HOUSEHOLD LISTS ONLY -- groceries, errands, to-dos. If the user is adding
    a BOOK ("add Project Hail Mary to my reading list"), that belongs on a
    Goodreads shelf, not here: use the Goodreads tools.

    Args:
        items: What to add, as the user said it. Several at once is fine --
            "milk, eggs and bread" adds three separate items.
        name: Which list. Leave empty for the grocery list, which is what
            "add milk" almost always means.
    """
    logger.info("add_to_list: items=%r name=%r", items, name)
    wanted = [i.strip() for i in re.split(r",|&|\band\b", items, flags=re.IGNORECASE) if i.strip()]
    if not wanted:
        return "What should I add?"
    try:
        lst = await _resolve_list(name)
        for label in wanted:
            await _request(
                "POST", f"/frames/{FRAME_ID}/lists/{lst['id']}/list_items",
                json={"label": label},
            )
    except SkylightError as err:
        return str(err)
    return f"Added {', '.join(wanted)} to the {lst.get('label')}."


@mcp.tool
async def check_off_list_item(item: str, name: str = "") -> str:
    """Mark an item on a list as done.

    Args:
        item: Which item, as the user said it.
        name: Which list. Leave empty for the grocery list.
    """
    logger.info("check_off_list_item: item=%r name=%r", item, name)
    try:
        lst = await _resolve_list(name)
        data = await _request(
            "GET", f"/frames/{FRAME_ID}/lists/{lst['id']}/list_items"
        )
        rows = [_flat(i) for i in data.get("data", [])]
        open_rows = {
            r["label"].lower(): r["id"]
            for r in rows if r.get("label") and r.get("status") != "complete"
        }
        if not open_rows:
            return f"Nothing left open on the {lst.get('label')}."
        item_id = _pick(item, open_rows, f"item on the {lst.get('label')}")
        await _request(
            "PATCH", f"/frames/{FRAME_ID}/lists/{lst['id']}/list_items/{item_id}",
            json={"status": "complete"},
        )
    except SkylightError as err:
        return str(err)
    return f"Checked off {item.strip()}."


@mcp.tool
async def create_list(name: str, kind: str = "to_do") -> str:
    """Create a new household list on the frame.

    HOUSEHOLD LISTS ONLY -- a shopping list, a to-do list. Reading lists live
    on Goodreads.

    Args:
        name: What to call it.
        kind: "shopping" for a grocery-style list, "to_do" for a checklist,
            or "other". Defaults to "to_do".
    """
    logger.info("create_list: name=%r kind=%r", name, kind)
    kinds = {"shopping", "to_do", "other"}
    key = _norm_kind(kind)
    if key not in kinds:
        return f"I can make a shopping, to-do or other list -- not '{kind}'."
    try:
        await _request(
            "POST", f"/frames/{FRAME_ID}/lists",
            json={"label": name.strip(), "kind": key},
        )
    except SkylightError as err:
        return str(err)
    return f"Created the {name.strip()} list."


def _norm_chore(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _split_owner(chore: str) -> tuple[str, str]:
    """Pull a possessive owner out of a chore phrase.

    "my workout" -> ("workout", "my"), "maitree's dishes" -> ("dishes",
    "maitree"), "our workout" -> ("workout", "our"). The ring often folds the
    person into the chore rather than passing them separately, and matching
    "myworkout" against "workout" would simply fail.
    """
    text = chore.strip()
    m = re.match(r"^(?P<owner>[A-Za-z]+)'s\s+(?P<rest>.+)$", text)
    if m:
        return m.group("rest").strip(), m.group("owner")
    m = re.match(r"^(?P<owner>my|mine|our|ours|the|a)\s+(?P<rest>.+)$", text, re.IGNORECASE)
    if m:
        owner = m.group("owner").lower()
        return m.group("rest").strip(), ("" if owner in {"the", "a"} else owner)
    return text, ""


def _norm_kind(kind: str) -> str:
    k = re.sub(r"[^a-z]", "", kind.lower())
    if k in {"shopping", "grocery", "groceries", "store"}:
        return "shopping"
    if k in {"todo", "tasks", "task", "checklist"}:
        return "to_do"
    return k or "to_do"


@mcp.tool
async def list_chores(who: str = "", days: int = 1) -> str:
    """Report chores that still need doing.

    Args:
        who: Whose chores, e.g. "Sarju". Leave empty for everyone's.
        days: How many days ahead to look. Defaults to today only.
    """
    logger.info("list_chores: who=%r days=%r", who, days)
    start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=max(1, days))
    try:
        data = await _request(
            "GET",
            f"/frames/{FRAME_ID}/chores"
            f"?after={_to_utc_z(start)}&before={_to_utc_z(end)}",
        )
        rows = data.get("data", [])
        wanted_ids: list[str] = []
        if who.strip():
            wanted_ids, unmatched = await _resolve_who(who.strip())
            if unmatched:
                return f"I don't know who {', '.join(unmatched)} is."
        names = {v: k for k, v in (await _category_map()).items()}
    except SkylightError as err:
        return str(err)

    cutoff = (start + timedelta(days=max(1, days))).date()
    pending = []
    for row in rows:
        a = _flat(row)
        if a.get("status") == "complete":
            continue
        # The API's window is inclusive of the day after `before`, so without
        # this every chore appeared twice -- today's and tomorrow's, listed
        # identically with nothing to tell them apart.
        if a.get("start") and a["start"] >= cutoff.isoformat():
            continue
        cat = ((row.get("relationships", {}).get("category") or {}).get("data") or {})
        cat_id = cat.get("id")
        if wanted_ids and cat_id not in wanted_ids:
            continue
        owner = names.get(cat_id, "").title()
        pending.append(f"{a.get('summary')}" + (f" ({owner})" if owner and not who.strip() else ""))

    if not pending:
        return "Nothing outstanding." if not who.strip() else f"Nothing outstanding for {who.strip()}."
    return f"{len(pending)} to do: " + ", ".join(pending) + "."


@mcp.tool
async def complete_chore(chore: str, who: str = "") -> str:
    """Mark today's chore done.

    Args:
        chore: Which chore, as the user said it, e.g. "workout".
        who: Whose chore, when more than one person has the same one today.
            Leave empty to use the default family member.

    IMPORTANT: if the result asks which person's chore is meant, relay that
    question rather than picking one.
    """
    logger.info("complete_chore: chore=%r who=%r", chore, who)
    # "my workout" / "maitree's dishes" fold the person into the chore name.
    chore, implied = _split_owner(chore)
    who = who.strip() or implied
    today = datetime.now(LOCAL_TZ).date()
    start = datetime.now(LOCAL_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    try:
        data = await _request(
            "GET",
            f"/frames/{FRAME_ID}/chores"
            f"?after={_to_utc_z(start)}&before={_to_utc_z(end)}",
        )
        names = {v: k for k, v in (await _category_map()).items()}

        # Keep every row. Keying a dict by chore name collapsed the four
        # daily Workouts -- two people over two days -- into one entry, and
        # the last silently won: tomorrow's, for the wrong person.
        rows = []
        for row in data.get("data", []):
            a = _flat(row)
            if a.get("status") == "complete":
                continue
            # The API's window is inclusive of the following day, so an
            # explicit date check is what actually confines this to today.
            if a.get("start") != today.isoformat():
                continue
            cat = ((row.get("relationships", {}).get("category") or {}).get("data") or {})
            a["_category_id"] = cat.get("id")
            a["_owner"] = names.get(cat.get("id"), "")
            rows.append(a)

        if not rows:
            return "Nothing's outstanding today."

        key = _norm_chore(chore)
        matches = [r for r in rows if _norm_chore(r.get("summary", "")) == key]
        if not matches:
            close = difflib.get_close_matches(
                key, [_norm_chore(r.get("summary", "")) for r in rows], n=1, cutoff=0.6
            )
            if close:
                matches = [r for r in rows if _norm_chore(r.get("summary", "")) == close[0]]
        if not matches:
            return (
                f"I don't have a chore called '{chore.strip()}' outstanding today. "
                f"Today's: {', '.join(sorted({r.get('summary', '') for r in rows}))}."
            )

        # Narrow by person. An unqualified request means the default member,
        # not "whoever sorts first" -- picking wrong writes to someone else's
        # chore history and moves their points.
        wanted = who or DEFAULT_MEMBER
        if len(matches) > 1 and wanted:
            ids, unmatched = await _resolve_who(wanted)
            if unmatched:
                return f"I don't know who {', '.join(unmatched)} is."
            narrowed = [r for r in matches if r["_category_id"] in ids]
            if narrowed:
                matches = narrowed
        if len(matches) > 1:
            owners = ", ".join(sorted(r["_owner"].title() for r in matches if r["_owner"]))
            return (
                f"{matches[0].get('summary')} is on more than one person's list today "
                f"({owners}). Whose should I check off?"
            )

        # "us"/"we" legitimately resolves to several people, so completing more
        # than one is expected rather than ambiguous.
        done = []
        for row in matches:
            body: dict = {"status": "complete", "instance_date": row.get("start")}
            if row.get("start_time"):
                body["instance_time"] = row["start_time"]
            # category_id is only accepted for an up-for-grabs chore; sending
            # it for a normally assigned one is a 422.
            if row.get("up_for_grabs") and row.get("_category_id"):
                body["category_id"] = row["_category_id"]
            await _request(
                "PUT",
                f"/frames/{FRAME_ID}/chores/{row.get('series') or row['id']}/completions",
                json=body,
            )
            done.append(row)
    except SkylightError as err:
        return str(err)

    summary = done[0].get("summary")
    points = sum(r.get("reward_points") or 0 for r in done)
    earned = f" That's {points} point{'s' if points != 1 else ''}." if points else ""
    owners = [r["_owner"].title() for r in done if r.get("_owner")]
    if len(done) > 1:
        return f"Marked {summary} done for {' and '.join(owners)} for today.{earned}"
    owner = f" for {owners[0]}" if owners else ""
    return f"Marked {summary} done{owner} for today.{earned}"


async def _point_balances() -> dict[str, int]:
    """category id -> current point balance.

    Points are per family member and live nowhere near the categories
    themselves, which carry no balance at all.
    """
    data = await _request("GET", f"/frames/{FRAME_ID}/reward_points")
    rows = data if isinstance(data, list) else data.get("data", [])
    return {str(r["category_id"]): r.get("current_point_balance", 0) for r in rows}


async def _one_person(who: str) -> tuple[str, str]:
    """Resolve a single person to (category_id, display name).

    Falls back to SKYLIGHT_DEFAULT_MEMBER, so "how many points do I have"
    works without naming anyone.
    """
    wanted = who.strip() or DEFAULT_MEMBER
    if not wanted:
        raise SkylightError("Whose points do you mean?")
    ids, unmatched = await _resolve_who(wanted)
    if unmatched:
        raise SkylightError(f"I don't know who {', '.join(unmatched)} is.")
    if not ids:
        raise SkylightError(f"I couldn't work out who '{who.strip()}' is.")
    names = {v: k for k, v in (await _category_map()).items()}
    return ids[0], names.get(ids[0], "").title()


@mcp.tool
async def list_rewards(who: str = "") -> str:
    """List the rewards available and how many points someone has.

    Use this for "what rewards are there", "how many points do I have", or
    before redeeming, to check whether it's affordable.

    Args:
        who: Whose points to report, e.g. "Maitree". Says "me"/"my" or leave
            empty for the default family member; "us" reports everyone.
    """
    logger.info("list_rewards: who=%r", who)
    try:
        data = await _request("GET", f"/frames/{FRAME_ID}/rewards")
        balances = await _point_balances()
        names = {v: k for k, v in (await _category_map()).items()}
        wanted = who.strip() or DEFAULT_MEMBER
        ids, unmatched = await _resolve_who(wanted) if wanted else ([], [])
        if unmatched:
            return f"I don't know who {', '.join(unmatched)} is."
    except SkylightError as err:
        return str(err)

    rows = [_flat(r) for r in data.get("data", [])]
    available = [r for r in rows if not r.get("redeemed_at")]

    parts = []
    for cat_id in (ids or balances.keys()):
        label = names.get(cat_id, "").title() or "Someone"
        parts.append(f"{label} has {balances.get(cat_id, 0)} points")
    balance_line = "; ".join(parts) + "." if parts else ""

    if not available:
        return (balance_line + " There aren't any rewards available right now.").strip()

    # Say what's actually within reach, not just what exists -- "5 points"
    # means nothing without knowing you have 5.
    top = max((balances.get(c, 0) for c in (ids or balances.keys())), default=0)
    listed = []
    for r in available:
        cost = r.get("point_value") or 0
        afford = "" if cost <= top else " (not enough points yet)"
        listed.append(f"{r.get('name')} for {cost}{afford}")
    return f"{balance_line} Rewards: " + ", ".join(listed) + "."


@mcp.tool
async def redeem_reward(reward: str, who: str = "") -> str:
    """Redeem a reward for someone, spending their points.

    Args:
        reward: Which reward, as the user said it, e.g. "massage".
        who: Who's redeeming it. Says "me"/"my" or leave empty for the
            default family member.

    IMPORTANT: if the result says there aren't enough points, relay that
    rather than redeeming something else.
    """
    logger.info("redeem_reward: reward=%r who=%r", reward, who)
    reward, implied = _split_owner(reward)
    who = who.strip() or implied
    try:
        cat_id, label = await _one_person(who)
        data = await _request("GET", f"/frames/{FRAME_ID}/rewards")
        rows = [_flat(r) for r in data.get("data", [])]
        options = {
            r["name"].lower(): r["id"]
            for r in rows if r.get("name") and not r.get("redeemed_at")
        }
        if not options:
            return "There aren't any rewards available to redeem."
        reward_id = _pick(reward, options, "reward")
        row = next(r for r in rows if r["id"] == reward_id)

        cost = row.get("point_value") or 0
        balance = (await _point_balances()).get(cat_id, 0)
        if balance < cost:
            # Better to say so than to let Skylight reject it, or worse,
            # accept it and quietly leave a negative balance.
            return (
                f"{label} has {balance} points and {row.get('name')} costs {cost} "
                f"-- {cost - balance} short."
            )

        # POST .../redeem, not a PATCH of redeemed_at: the timestamp is a
        # result of redeeming, not the thing that causes it.
        await _request(
            "POST", f"/frames/{FRAME_ID}/rewards/{reward_id}/redeem",
            json={"category_id": cat_id},
        )
    except SkylightError as err:
        return str(err)
    return (
        f"Redeemed {row.get('name')} for {label}. That's {cost} points, "
        f"leaving {balance - cost}."
    )


@mcp.tool
async def add_to_meal_plan(meal: str, when: str = "", meal_type: str = "") -> str:
    """Put a meal on the meal plan.

    Args:
        meal: What's being eaten, as the user said it, e.g. "tacos". Free
            text -- it doesn't have to be a saved recipe.
        when: Which day, e.g. "friday", "tomorrow", or "2026-09-04".
            Defaults to today.
        meal_type: Breakfast, lunch or dinner. Defaults to dinner.
    """
    logger.info("add_to_meal_plan: meal=%r when=%r meal_type=%r", meal, when, meal_type)
    if not meal.strip():
        return "What should I add to the meal plan?"
    try:
        day = _meal_date(when)
        data = await _request("GET", f"/frames/{FRAME_ID}/meals/categories")
        cats = [_flat(c) for c in data.get("data", [])]
        enabled = {c["label"].lower(): c["id"] for c in cats
                   if c.get("label") and c.get("enabled")}
        if not enabled:
            return "The frame doesn't have any meal categories set up."
        wanted = meal_type.strip() or "dinner"
        cat_id = _pick(wanted, enabled, "meal type")
        label = next(c["label"] for c in cats if c["id"] == cat_id)
        await _request(
            "POST", f"/frames/{FRAME_ID}/meals/sittings",
            json={
                "meal_category_id": cat_id,
                "date": day.isoformat(),
                # Free text, deliberately: no recipe is linked, so summary
                # carries the name. Sending both a summary and a recipe id
                # is a 422 -- the sitting takes its name from the recipe.
                "summary": meal.strip(),
            },
        )
    except SkylightError as err:
        return str(err)
    return f"Put {meal.strip()} on the plan for {label.lower()} on {day:%A}."


@mcp.tool
async def show_meal_plan(days: int = 7) -> str:
    """Report what meals are planned.

    Args:
        days: How many days ahead to look. Defaults to a week.
    """
    logger.info("show_meal_plan: days=%r", days)
    start = datetime.now(LOCAL_TZ).date()
    try:
        data = await _request(
            "GET",
            f"/frames/{FRAME_ID}/meals/sittings?date_min={start.isoformat()}"
            f"&date_max={(start + timedelta(days=max(1, days))).isoformat()}",
        )
    except SkylightError as err:
        return str(err)
    rows = [_flat(r) for r in data.get("data", [])]
    if not rows:
        return "Nothing's planned for the next few days."
    parts = []
    for r in rows:
        when = r.get("date") or r.get("start") or ""
        what = r.get("summary") or r.get("label") or "something"
        parts.append(f"{what} on {when}" if when else what)
    return "Planned: " + "; ".join(parts) + "."


async def healthz(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


app = mcp.http_app(path="/mcp")
app.add_middleware(BearerAuth)
app.router.routes.insert(0, __import__("starlette.routing", fromlist=["Route"]).Route("/healthz", healthz))

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
