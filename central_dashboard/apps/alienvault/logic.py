"""
AlienVault USM Anywhere — Synchronous logic (ported from async client).

Key design decisions ported from the async reference implementation:
  • Module-level token cache with TTL — avoid per-request auth overhead
  • status sent as list-of-tuples so requests sends ?status=open&status=closed&...
    (NOT ?status=open%2Cclosed%2C... which AV API silently ignores)
  • Fallback retry without status filter when API returns non-200
  • _resolve_deployment_url tries fqdn → id (strips cn:// prefix) → name
  • fetch_all_deployments uses ThreadPoolExecutor(max_workers=4) for concurrency
"""
import logging
import os
import time
import requests
import pandas as pd
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("alienvault.logic")

# ─── Env helpers ──────────────────────────────────────────────────────────────

def _get_subdomain() -> str:
    return os.environ.get("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud").strip()

def _get_creds() -> tuple[str, str]:
    return (
        os.environ.get("AV_CLIENT_ID", ""),
        os.environ.get("AV_CLIENT_SECRET", ""),
    )

# ─── Token cache (module-level) ───────────────────────────────────────────────

_token_cache: dict = {"token": None, "expiry": 0.0, "base_path": "/api/1.1"}


def get_token() -> str:
    """
    Get OAuth2 bearer token from the central portal.
    Caches with TTL so we don't re-auth on every request.
    Raises RuntimeError if all endpoints fail.
    """
    global _token_cache
    if _token_cache["token"] and time.time() < _token_cache["expiry"]:
        return _token_cache["token"]

    sub = _get_subdomain()
    cid, csec = _get_creds()
    base = f"https://{sub}"

    for ep in (
        "/api/1.1/oauth/token",
        "/api/1.0/oauth/token",
        "/api/2.0/oauth/token",
        "/oauth/token",
        "/oauth2/token",
    ):
        try:
            resp = requests.post(
                base + ep,
                data={"grant_type": "client_credentials"},
                auth=(cid, csec),
                timeout=20,
            )
            if resp.status_code == 200:
                body = resp.json()
                token = body.get("access_token", "")
                if token:
                    expires_in = int(body.get("expires_in", 3600))
                    base_path = (
                        "/api/1.1" if "1.1" in ep
                        else "/api/2.0" if "2.0" in ep
                        else "/api/1.1"
                    )
                    _token_cache = {
                        "token": token,
                        "expiry": time.time() + expires_in - 60,
                        "base_path": base_path,
                    }
                    logger.info(f"AV: token acquired via {ep} (base_path={base_path})")
                    return token
                logger.warning(f"AV auth {ep} → 200 but no access_token")
            else:
                logger.warning(f"AV auth {ep} → HTTP {resp.status_code}")
        except Exception as e:
            logger.warning(f"AV auth {ep} → {e}")

    raise RuntimeError(
        f"AV: all OAuth endpoints failed for {sub}. "
        "Check AV_CLIENT_ID, AV_CLIENT_SECRET, AV_SUBDOMAIN env vars."
    )


# ─── Deployment URL resolution ─────────────────────────────────────────────────

def _resolve_deployment_url(dep: dict) -> str:
    """
    Extract a usable HTTPS base URL from a deployment dict.
    Priority: url → fqdn → hostname → base_url → HAL self-link → id field → name
    """
    for key in ("url", "fqdn", "hostname", "base_url"):
        val = dep.get(key, "")
        if val:
            return (f"https://{val}" if not val.startswith("http") else val).rstrip("/")

    # HAL self-link
    self_link = (dep.get("_links") or {}).get("self", {}).get("href", "")
    if self_link and "alienvault.cloud" in self_link:
        from urllib.parse import urlparse as _up
        p = _up(self_link)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"

    # id field — may look like "cn://etranzact2.alienvault.cloud"
    dep_id = dep.get("id", "")
    if dep_id and "://" in dep_id:
        host = dep_id.split("://")[1].split("/")[0]
        if host:
            return f"https://{host}"

    # name field — bare name or alienvault.cloud domain
    name = dep.get("name", "").strip()
    if name:
        if "alienvault.cloud" in name:
            return (f"https://{name}" if not name.startswith("http") else name).rstrip("/")
        if " " not in name and not name.startswith("http"):
            return f"https://{name}.alienvault.cloud"

    return ""


# ─── Deployments ──────────────────────────────────────────────────────────────

def get_deployments() -> list[dict]:
    """
    Return all AV deployments visible to the central account.
    Each dict has _url (resolved base URL) added.
    """
    try:
        token = get_token()
    except RuntimeError as e:
        logger.error(f"AV get_deployments: {e}")
        return []

    subdomain = _get_subdomain()
    base = f"https://{subdomain}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base_path = _token_cache.get("base_path", "/api/1.1")

    paths_raw = [
        f"{base_path.rstrip('/')}/deployments",
        "/api/2.0/deployments",
        "/api/1.1/deployments",
        "/deployments",
    ]
    seen: set = set()
    paths = [p for p in paths_raw if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]

    for path in paths:
        try:
            resp = requests.get(base + path, headers=headers, timeout=30)
            logger.info(f"AV deployments {path} → HTTP {resp.status_code}")
            if resp.status_code != 200:
                continue
            data = resp.json()

            if "_embedded" in data:
                embedded = data["_embedded"]
                deps = (
                    embedded.get("deployments")
                    or embedded.get("tenantList")
                    or embedded.get("tenants")
                    or embedded.get("subscriptions")
                    or next(iter(embedded.values()), [])
                )
            elif isinstance(data, list):
                deps = data
            else:
                deps = (
                    data.get("deployments")
                    or data.get("tenants")
                    or data.get("data")
                    or []
                )

            logger.info(f"AV: {len(deps)} deployment objects from {path}")
            if not deps:
                continue

            logger.info(f"AV: first dep keys={list(deps[0].keys())}")
            for d in deps:
                d["_url"] = _resolve_deployment_url(d)
                logger.info(f"AV dep '{d.get('name','?')}' → _url={d['_url']!r}")
            return deps

        except Exception as e:
            logger.warning(f"AV deployments {path} → {e}")

    logger.error("AV: no deployments found")
    return []


# ─── Per-deployment alarm fetch ────────────────────────────────────────────────

def fetch_alarms_for_deployment(
    dep_url: str,
    token: str,
    start_ms: int,
    end_ms: int,
    dep_name: str = "",
    max_records: int = 5000,
) -> list[dict]:
    """
    Fetch alarms from one deployment's /api/2.0/alarms.

    Critical fixes (ported from working async implementation):
    - Uses timestamp_occured_gte (NOT timestamp_received_gte — that field is ignored by AV API)
    - Applies a 30-day pre-buffer so late-arriving alarms are captured,
      then filters client-side by timestamp_received to narrow to the actual range
    - NO status filter in the API call (done client-side after fetch)
    - Follows HAL _links.next.href for pagination
    """
    if not dep_url:
        return []

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = dep_url.rstrip("/") + "/api/2.0/alarms"

    # 30-day pre-buffer + 1-hour WAT offset — alarms can arrive weeks after they occurred.
    # AV API only indexes by timestamp_occured; timestamp_received can be much later.
    PRE_BUFFER_MS  = 30 * 86_400_000   # 30 days
    POST_BUFFER_MS =  1 * 86_400_000   # 1 day
    TZ_OFFSET_MS   =      3_600_000    # WAT = UTC+1
    adj_start = start_ms - PRE_BUFFER_MS - TZ_OFFSET_MS
    adj_end   = end_ms   + POST_BUFFER_MS - TZ_OFFSET_MS + 59_000

    # API params — NO status filter (done client-side), correct field name is occured not received
    base_params = {
        "timestamp_occured_gte": adj_start,
        "timestamp_occured_lte": adj_end,
        "sort": "timestamp_occured,desc",
        "size": 100,
    }

    all_alarms: list[dict] = []
    page_url: str | None = url
    first_page = True

    while page_url and len(all_alarms) < max_records:
        try:
            resp = requests.get(
                page_url,
                headers=headers,
                params=base_params if first_page else None,
                timeout=30,
            )
            first_page = False
            logger.info(f"AV alarms {dep_name or dep_url}: HTTP {resp.status_code}")

            if resp.status_code == 404:
                break
            if resp.status_code == 503:
                time.sleep(1)
                resp = requests.get(page_url, headers=headers, timeout=30)
            if resp.status_code != 200:
                logger.warning(f"AV: {dep_name} HTTP {resp.status_code} — stopping")
                break

            body = resp.json()
            if first_page is False and page_url == url:
                pm = body.get("page", {})
                logger.info(f"AV: {dep_name} page_meta={pm}")

            batch = body.get("_embedded", {}).get("alarms", [])
            if dep_name:
                for a in batch:
                    a["_deployment_name"] = dep_name
            all_alarms.extend(batch)

            # HAL pagination — follow _links.next.href
            next_href = body.get("_links", {}).get("next", {}).get("href")
            if next_href:
                page_url = (
                    next_href if next_href.startswith("http")
                    else dep_url.rstrip("/") + next_href
                )
            else:
                page_url = None

        except requests.exceptions.ConnectionError as ce:
            logger.warning(f"AV alarms DNS/connection error for {dep_url}: {ce}")
            break
        except Exception as e:
            logger.error(f"AV alarms fetch error ({dep_name}): {e}")
            break

    # Client-side filter: keep only alarms whose timestamp_received is in the original range
    filtered: list[dict] = []
    for a in all_alarms:
        ts = a.get("timestamp_received")
        if isinstance(ts, str):
            try:
                import datetime as _dt
                parsed = _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
                ts = int(parsed.timestamp() * 1000)
            except Exception:
                ts = 0
        if isinstance(ts, (int, float)) and ts > 0:
            if ts < start_ms or ts > end_ms:
                continue
        filtered.append(a)

    logger.info(
        f"AV: {dep_name or dep_url} → fetched {len(all_alarms)}, "
        f"after time filter {len(filtered)}"
    )
    return filtered[:max_records]


def fetch_events_for_deployment(
    dep_url: str,
    token: str,
    start_ms: int,
    end_ms: int,
    dep_name: str = "",
    max_records: int = 5000,
) -> list[dict]:
    """Fetch events from one deployment using correct timestamp field name."""
    if not dep_url:
        return []

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    url = dep_url.rstrip("/") + "/api/2.0/events"

    TZ_OFFSET_MS = 3_600_000
    adj_start = start_ms - TZ_OFFSET_MS
    adj_end   = end_ms   - TZ_OFFSET_MS + 59_000

    base_params = {
        "timestamp_occured_gte": adj_start,
        "timestamp_occured_lte": adj_end,
        "sort": "timestamp_occured,desc",
        "size": 500,
    }
    all_events: list[dict] = []
    page_url: str | None = url
    first_page = True

    while page_url and len(all_events) < max_records:
        try:
            resp = requests.get(
                page_url,
                headers=headers,
                params=base_params if first_page else None,
                timeout=30,
            )
            first_page = False
            if resp.status_code != 200:
                break
            body = resp.json()

            # Parse embedded events (try multiple key names)
            emb = body.get("_embedded", {})
            batch = (
                emb.get("events")
                or emb.get("eventResourceList")
                or emb.get("eventResources")
                or []
            )
            if not batch:
                break

            if dep_name:
                for e in batch:
                    e["_deployment_name"] = dep_name
            all_events.extend(batch)

            next_href = body.get("_links", {}).get("next", {}).get("href")
            if next_href:
                page_url = (
                    next_href if next_href.startswith("http")
                    else dep_url.rstrip("/") + next_href
                )
            else:
                page_url = None

        except requests.exceptions.ConnectionError:
            break
        except Exception as e:
            logger.error(f"AV events fetch error ({dep_name}): {e}")
            break

    logger.info(f"AV: {dep_name or dep_url} → {len(all_events)} events")
    return all_events[:max_records]


# ─── Multi-deployment parallel fetch ──────────────────────────────────────────

def fetch_all_deployments(
    token: str,
    start_ms: int,
    end_ms: int,
    max_workers: int = 4,
) -> tuple[list[dict], list[dict]]:
    """
    Fetch alarms and events from ALL resolvable deployments in parallel.
    Uses semaphore-style concurrency (max_workers=4) matching the async client.
    Returns (all_alarms, all_events).
    """
    deps = get_deployments()
    if not deps:
        logger.warning("AV fetch_all_deployments: no deployments found")
        return [], []

    all_alarms: list[dict] = []
    all_events: list[dict] = []

    def _fetch_one(d: dict) -> tuple[list, list]:
        dep_url = d.get("_url", "")
        dep_name = d.get("name", "Unknown")
        if not dep_url:
            logger.warning(f"AV: {dep_name} has no resolved URL — skipping")
            return [], []
        a = fetch_alarms_for_deployment(dep_url, token, start_ms, end_ms, dep_name)
        e = fetch_events_for_deployment(dep_url, token, start_ms, end_ms, dep_name)
        logger.info(f"AV dep '{dep_name}': {len(a)} alarms, {len(e)} events")
        return a, e

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_fetch_one, d): d for d in deps}
        for fut in as_completed(futures):
            try:
                a, e = fut.result()
                all_alarms.extend(a)
                all_events.extend(e)
            except Exception as ex_err:
                dep = futures[fut]
                logger.error(f"AV: {dep.get('name')} gather error: {ex_err}")

    logger.info(
        f"AV fetch_all_deployments total: {len(all_alarms)} alarms, {len(all_events)} events"
    )
    return all_alarms, all_events


# ─── Data processing ──────────────────────────────────────────────────────────

def _safe_vc(series, name_col, count_col, top=30):
    """Return value_counts as list of dicts."""
    vc = series.value_counts().head(top).reset_index()
    vc.columns = [name_col, count_col]
    return vc.to_dict(orient="records")


def process_alarms(alarms: list) -> dict:
    if not alarms:
        return {}
    df = pd.json_normalize(alarms)

    def safe_col(col):
        return df[col] if col in df.columns else pd.Series(dtype=str)

    top_methods  = _safe_vc(safe_col("rule_method"),   "Method",   "Count")
    top_strategy = _safe_vc(safe_col("rule_strategy"), "Strategy", "Count")
    top_intent   = _safe_vc(safe_col("rule_intent"),   "Intent",   "Count")
    severity     = _safe_vc(safe_col("priority_label"), "Severity", "Count")

    m = safe_col("rule_method")
    failed_logons = [
        {"Failed Logon Type": "Nonexistent Account",
         "Count": int((m == "Failed Logon to Nonexistent Account").sum())},
        {"Failed Logon Type": "Default Account",
         "Count": int((m == "Failed Logon to Default Account").sum())},
        {"Failed Logon Type": "Disabled Account",
         "Count": int((m == "Failed Logon to Disabled Account").sum())},
    ]
    user_act_keys = [
        "User Account was Unlocked",
        "A User Account was Disabled",
        "User added to Admin role",
        "User Added to Enterprise Admins Group",
        "Create User",
        "User Added to Local Administrators Group",
    ]
    user_activities = [{"Activity": k, "Count": int((m == k).sum())} for k in user_act_keys]

    unlocked_users: list = []
    disabled_users: list = []
    if "source_username" in df.columns:
        unlocked_users = _safe_vc(df.loc[m == "User Account was Unlocked", "source_username"], "Username", "Count")
        disabled_users = _safe_vc(df.loc[m == "A User Account was Disabled", "source_username"], "Username", "Count")

    return {
        "top_methods":     top_methods,
        "top_strategy":    top_strategy,
        "top_intent":      top_intent,
        "failed_logons":   failed_logons,
        "user_activities": user_activities,
        "unlocked_users":  unlocked_users,
        "disabled_users":  disabled_users,
        "severity":        severity,
    }


def process_events(events: list) -> dict:
    if not events:
        return {}
    df = pd.json_normalize(events)

    sensor_field = None
    for f in ["sensor", "data_source", "source_name", "plugin", "sensor_name"]:
        if f in df.columns:
            sensor_field = f
            break

    sensor_list = []
    top_event_names = []
    events_by_sensor: dict = {}

    if sensor_field:
        sensors = df[sensor_field].dropna().unique().tolist()
        sensor_list = [{"Sensor Name": s} for s in sensors]
        if "event_name" in df.columns:
            top_event_names = _safe_vc(df["event_name"], "Event Name", "Count", top=20)
            for sensor in sensors:
                mask = df[sensor_field] == sensor
                ev = _safe_vc(df.loc[mask, "event_name"], "Event Name", "Count", top=20)
                events_by_sensor[str(sensor)] = ev
    elif "event_name" in df.columns:
        top_event_names = _safe_vc(df["event_name"], "Event Name", "Count", top=20)

    return {
        "sensor_list":      sensor_list,
        "top_event_names":  top_event_names,
        "events_by_sensor": events_by_sensor,
    }


def export_to_excel(alarm_data: dict, event_data: dict) -> BytesIO:
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
        def _write(rows, sheet):
            if rows:
                pd.DataFrame(rows).to_excel(writer, index=False, sheet_name=sheet)

        _write(alarm_data.get("top_methods"),     "Top 30 Methods")
        _write(alarm_data.get("top_strategy"),    "Top 30 Strategy")
        _write(alarm_data.get("top_intent"),      "Top 30 Intent")
        _write(alarm_data.get("failed_logons"),   "Failed Logons")
        _write(alarm_data.get("user_activities"), "User Activities")
        _write(alarm_data.get("unlocked_users"),  "Unlocked Accounts")
        _write(alarm_data.get("disabled_users"),  "Disabled Accounts")
        _write(alarm_data.get("severity"),        "Alarms by Severity")
        _write(event_data.get("sensor_list"),     "Sensors List")
        _write(event_data.get("top_event_names"), "Top 20 Events Overall")
        for sensor, rows in (event_data.get("events_by_sensor") or {}).items():
            sname = f"Events_{sensor}"[:31].replace("/", "_").replace("\\", "_")
            _write(rows, sname)

    buf.seek(0)
    return buf
