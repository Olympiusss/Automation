"""
AlienVault Alarm Extractor — Backend Logic
Ported from contentapp.py (Streamlit) to plain Python for Flask integration.
"""
import requests
import pandas as pd
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import os

# ─── Config ───────────────────────────────────────────────────
# Read all credentials fresh per-call via helpers — never cache at import time
# because Railway injects env vars after the module is first imported.
CLIENT_ID     = os.environ.get("AV_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AV_CLIENT_SECRET", "")

def _get_subdomain() -> str:
    """Read AV_SUBDOMAIN fresh every call so Railway env updates take effect."""
    return os.environ.get("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud").strip()

# Keep a module-level alias for backwards compat (not used for live calls)
SUBDOMAIN = _get_subdomain()


def get_token(subdomain: str | None = None, client_id: str | None = None, client_secret: str | None = None) -> str:
    """
    Obtain an OAuth2 bearer token from the AV central portal.
    Tries /api/1.1/, /api/2.0/, /api/1.0/ and bare /oauth/token in order
    and returns the first successful access_token.
    Raises RuntimeError if every endpoint fails.
    """
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")
    _sub = subdomain or SUBDOMAIN
    _id  = client_id  or CLIENT_ID
    _sec = client_secret or CLIENT_SECRET
    base = f"https://{_sub}"
    for ep in ("/api/1.1/oauth/token", "/api/2.0/oauth/token",
               "/api/1.0/oauth/token", "/oauth/token"):
        try:
            resp = requests.post(
                base + ep,
                data={"grant_type": "client_credentials"},
                auth=(_id, _sec),
                timeout=20,
            )
            if resp.status_code == 200:
                # Always call resp.json() directly — requests parses JSON
                # regardless of the Content-Type header sent by the server
                try:
                    body = resp.json()
                except Exception:
                    body = {}
                token = body.get("access_token", "")
                if token:
                    _logger.info(f"AV token acquired via {ep}")
                    return token
                _logger.warning(f"AV auth {ep} -> 200 but no access_token in response: {list(body.keys())}")
            else:
                _logger.warning(f"AV auth {ep} -> HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as _e:
            _logger.warning(f"AV auth {ep} -> {_e}")
    raise RuntimeError(
        f"AV: all OAuth endpoints failed for subdomain '{_sub}'. "
        "Check AV_CLIENT_ID, AV_CLIENT_SECRET, and AV_SUBDOMAIN env vars."
    )


def get_deployments() -> list[dict]:
    """
    Return all AV deployments visible to the central account.
    Each dict has: name, displayName, _url (the deployment's own API base URL).
    """
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")

    try:
        token = get_token()
    except RuntimeError as _auth_err:
        _logger.error(f"AV get_deployments: token failed — {_auth_err}")
        return []

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"https://{SUBDOMAIN}"

    # Try all known multi-tenant endpoint paths used by AV USM Anywhere
    paths = [
        "/api/2.0/deployments", "/api/1.1/deployments",
        "/api/2.0/tenants",     "/api/1.1/tenants",
        "/api/2.0/subscriptions","/api/1.1/subscriptions",
        "/api/2.0/organizations","/api/1.1/organizations",
        "/deployments",          "/tenants",
    ]
    for path in paths:
        try:
            resp = requests.get(base + path, headers=headers, timeout=30)
            _logger.info(f"AV deployments {path} -> HTTP {resp.status_code}")
            if resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                _logger.warning(f"AV: {path} returned 200 but non-JSON body")
                continue
            _logger.info(f"AV deployments {path} raw: type={type(data).__name__}, "
                         f"keys={list(data.keys())[:10] if isinstance(data, dict) else f'list({len(data)} items)'}")

            if "_embedded" in data:
                embedded = data["_embedded"]
                deps = (
                    embedded.get("deployments")
                    or embedded.get("tenantList")
                    or embedded.get("tenants")
                    or embedded.get("subscriptions")
                    or embedded.get("organizations")
                    or next(iter(embedded.values()), [])
                )
            elif isinstance(data, list):
                deps = data
            else:
                deps = (data.get("deployments")
                        or data.get("tenants")
                        or data.get("subscriptions")
                        or data.get("organizations")
                        or data.get("data")
                        or [])
            _logger.info(f"AV: {len(deps)} raw deployment objects from {path}")
            if deps:
                _logger.info(f"AV: first dep keys = {list(deps[0].keys())}")
                # Resolve each deployment's own base URL from whatever field AV provides
                for d in deps:
                    _url = ""
                    # 1. Explicit URL-like fields
                    for field in ("url", "domain", "apiUrl", "baseUrl", "hostname",
                                  "fqdn", "api_url", "base_url", "instanceUrl"):
                        raw = d.get(field, "")
                        if raw:
                            _url = ("https://" + raw if not raw.startswith("http") else raw).rstrip("/")
                            break
                    # 2. HAL _links.self.href (common AV REST pattern)
                    if not _url:
                        href = (d.get("_links") or {}).get("self", {}).get("href", "")
                        if href and "alienvault" in href:
                            from urllib.parse import urlparse as _up
                            p = _up(href)
                            if p.scheme and p.netloc:
                                _url = f"{p.scheme}://{p.netloc}"
                    # 3. Construct from name if it looks like a subdomain
                    if not _url:
                        name = d.get("name", "")
                        if name and "." not in name and " " not in name and name:
                            _url = f"https://{name}.alienvault.cloud"
                        elif name and "alienvault" in name:
                            _url = f"https://{name}" if not name.startswith("http") else name
                    d["_url"] = _url
                    _logger.info(
                        f"AV dep '{d.get('name','?')}' -> _url={_url!r}"
                    )
                return deps
            else:
                _logger.warning(f"AV: {path} returned 200 but 0 deployments")
        except Exception as _e:
            _logger.warning(f"AV deployments {path} -> {_e}")
    _logger.error("AV: no deployments found across all path variants")
    return []


def _get_deployment_token(dep_url: str, fallback_token: str) -> str:
    """
    Get an OAuth token scoped to a specific deployment.
    In AV MSP setups the central portal token is NOT valid against child
    deployment APIs — each deployment needs its own token obtained from
    its own OAuth endpoint using the same client credentials.
    Falls back to the central token if the deployment auth fails.
    """
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")
    if not dep_url:
        return fallback_token
    try:
        from urllib.parse import urlparse as _up
        netloc = _up(dep_url).netloc  # e.g. esentry-nfr.alienvault.cloud
        if not netloc:
            return fallback_token
        dep_token = get_token(subdomain=netloc)
        _logger.info(f"AV: deployment token obtained for {netloc}")
        return dep_token
    except Exception as _e:
        _logger.warning(f"AV: deployment token failed for {dep_url} ({_e}) — using central token")
        return fallback_token


def fetch_alarms_for_deployment(dep_url: str, token: str, start_ms: int, end_ms: int, max_records: int = 5000) -> list:
    """Fetch alarms from a specific deployment URL (per-client fetch)."""
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")
    if not dep_url:
        return []
    # Get a token valid for this specific deployment
    dep_token = _get_deployment_token(dep_url, token)
    headers = {"Authorization": f"Bearer {dep_token}", "Content-Type": "application/json"}
    base_params = {
        "timestamp_received_gte": start_ms,
        "timestamp_received_lte": end_ms,
        "sort": "timestamp_received,desc",
        "suppressed": "false",
        "size": 500,
        "status": ["open", "closed", "in_review"],
    }
    # Try api/1.1 first (confirmed working for this AV instance), then api/2.0
    for api_path in ("/api/1.1/alarms", "/api/2.0/alarms"):
        url = dep_url.rstrip("/") + api_path
        all_alarms = []
        for page in range(20):
            try:
                p = {**base_params, "page": page}
                resp = requests.get(url, headers=headers, params=p, timeout=45)
                _logger.info(f"AV alarms {api_path} page {page}: HTTP {resp.status_code}")
                if resp.status_code == 404:
                    break  # try next api_path
                if resp.status_code != 200:
                    _logger.error(f"AV alarms {url} HTTP {resp.status_code}: {resp.text[:200]}")
                    break
                batch = (resp.json().get("_embedded") or {}).get("alarms", [])
                if not batch:
                    break
                all_alarms.extend(batch)
                if len(batch) < 500 or len(all_alarms) >= max_records:
                    break
            except Exception as _e:
                _logger.error(f"AV alarms fetch error: {_e}")
                break
        if all_alarms:
            _logger.info(f"AV: {len(all_alarms)} alarms from {url}")
            return all_alarms[:max_records]
        if resp.status_code != 404:
            break  # non-404 failure — no point trying other path
    _logger.warning(f"AV: 0 alarms fetched from {dep_url}")
    return []


def fetch_events_for_deployment(dep_url: str, token: str, start_ms: int, end_ms: int, max_records: int = 5000) -> list:
    """Fetch events from a specific deployment URL."""
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")
    if not dep_url:
        return []
    dep_token = _get_deployment_token(dep_url, token)
    headers = {"Authorization": f"Bearer {dep_token}", "Content-Type": "application/json"}
    base_params = {
        "timestamp_received_gte": start_ms,
        "timestamp_received_lte": end_ms,
        "sort": "timestamp_received,desc",
        "size": 500,
    }
    # Try api/1.1 first, then api/2.0
    for api_path in ("/api/1.1/events", "/api/2.0/events"):
        url = dep_url.rstrip("/") + api_path
        all_events = []
        for page in range(20):
            try:
                resp = requests.get(url, headers=headers,
                                    params={**base_params, "page": page}, timeout=45)
                _logger.info(f"AV events {api_path} page {page}: HTTP {resp.status_code}")
                if resp.status_code == 404:
                    break
                if resp.status_code != 200:
                    _logger.error(f"AV events {url} HTTP {resp.status_code}: {resp.text[:200]}")
                    break
                batch = (resp.json().get("_embedded") or {}).get("eventResources", [])
                if not batch:
                    break
                all_events.extend(batch)
                if len(batch) < 500 or len(all_events) >= max_records:
                    break
            except Exception as _e:
                _logger.error(f"AV events fetch error: {_e}")
                break
        if all_events:
            _logger.info(f"AV: {len(all_events)} events from {url}")
            return all_events[:max_records]
        if resp.status_code != 404:
            break
    _logger.warning(f"AV: 0 events fetched from {dep_url}")
    return []


def _fetch_page(url, headers, params, page_num, response_key, timeout=60):
    try:
        p = params.copy()
        p["page"] = page_num
        r = requests.get(url, headers=headers, params=p, timeout=timeout)
        if r.status_code == 200:
            return r.json().get("_embedded", {}).get(response_key, [])
    except Exception:
        pass
    return []


def fetch_all_parallel(endpoint, params, headers, max_records=20000, dep_id: str = "") -> list:
    """
    Fetch all pages of an endpoint from the CENTRAL AV portal.
    Tries /api/1.1/ first (confirmed working), then /api/2.0/.
    Optionally filters by dep_id (deployment UUID from /api/1.1/deployments).
    """
    import logging as _log
    _logger = _log.getLogger("alienvault.logic")
    response_key_map = {"events": "eventResources", "alarms": "alarms"}
    response_key = response_key_map.get(endpoint, endpoint)
    subdomain = _get_subdomain()  # fresh read every time

    for api_ver in ("1.1", "2.0"):
        url = f"https://{subdomain}/api/{api_ver}/{endpoint}"
        p = params.copy()
        p["size"] = 500
        p["page"] = 0
        if dep_id:
            # Try common AlienVault MSP deployment filter param names
            p["deploymentId"] = dep_id
        _logger.info(f"AV global fetch: GET {url} page=0 dep_id={dep_id!r}")
        try:
            r = requests.get(url, headers=headers, params=p, timeout=60)
            _logger.info(f"AV global {api_ver}/{endpoint}: HTTP {r.status_code}")
            if r.status_code == 404:
                continue  # try next api version
            if r.status_code != 200:
                _logger.error(f"AV global {url}: HTTP {r.status_code}: {r.text[:200]}")
                return []
            try:
                data = r.json()
            except Exception:
                _logger.error(f"AV global {url}: non-JSON response")
                return []

            # Handle both embedded and flat list responses
            if "_embedded" in data:
                all_data = (data["_embedded"].get(response_key)
                            or data["_embedded"].get("alarms")
                            or data["_embedded"].get("eventResources")
                            or next(iter(data["_embedded"].values()), []))
            elif isinstance(data, list):
                all_data = data
            else:
                all_data = data.get(response_key, data.get("data", []))

            page_info = data.get("page", {})
            total_pg  = page_info.get("totalPages", 1)
            _logger.info(f"AV global: {len(all_data)} on page 0, totalPages={total_pg}")

            if not all_data and total_pg == 0:
                _logger.info(f"AV global: 0 results for {endpoint} (empty date range or no data)")
                return []

            max_pages = min(total_pg, (max_records // 500) + 1, 200)
            if max_pages <= 1:
                return all_data[:max_records]

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {
                    executor.submit(_fetch_page, url, headers, p, pg, response_key): pg
                    for pg in range(1, max_pages)
                }
                for future in as_completed(futures):
                    items = future.result()
                    if items:
                        all_data.extend(items)
                    if len(all_data) >= max_records:
                        break

            _logger.info(f"AV global: {len(all_data)} total {endpoint}")
            return all_data[:max_records]

        except Exception as _e:
            _logger.error(f"AV global fetch_all_parallel error ({api_ver}): {_e}")
            continue

    return []


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
    severity     = _safe_vc(safe_col("priority_label"),"Severity", "Count")

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

    unlocked_users = []
    disabled_users = []
    if "source_username" in df.columns:
        unlocked_mask = m == "User Account was Unlocked"
        disabled_mask = m == "A User Account was Disabled"
        unlocked_users = _safe_vc(df.loc[unlocked_mask, "source_username"], "Username", "Count")
        disabled_users = _safe_vc(df.loc[disabled_mask, "source_username"], "Username", "Count")

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
    events_by_sensor = {}

    if sensor_field:
        sensors = df[sensor_field].dropna().unique().tolist()
        sensor_list = [{"Sensor Name": s} for s in sensors]
        if "event_name" in df.columns:
            top_event_names = _safe_vc(df["event_name"], "Event Name", "Count", top=20)
            for sensor in sensors:
                mask = df[sensor_field] == sensor
                ev   = _safe_vc(df.loc[mask, "event_name"], "Event Name", "Count", top=20)
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
