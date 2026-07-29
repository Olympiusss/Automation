"""
AlienVault USM Anywhere — Synchronous logic.

Uses httpx.Client(verify=False) to match the working SOC dashboard async client.
EXACT same params as soc_dashboard/fetcher.py _fetch_alarms_one:
  - timestamp_received_gte / timestamp_received_lte
  - status as list-of-tuples: [("status","open"),("status","closed"),("status","in_review")]
  - suppressed=false
  - fallback retry without status filter on non-200

Per-deployment token is tried first (exactly as SOC fetcher does), falls back to
central token if the deployment doesn't support its own OAuth.
"""
import logging
import os
import time
import httpx
import pandas as pd
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("alienvault.logic")

# ─── Suppress SSL warnings (verify=False) ────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Env helpers ──────────────────────────────────────────────────────────────

def _get_subdomain() -> str:
    val = os.environ.get("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud")
    return val.strip().strip('"').strip("'").replace("https://", "").replace("http://", "").rstrip("/")

def _get_creds() -> tuple[str, str]:
    return (
        os.environ.get("AV_CLIENT_ID", "").strip().strip('"').strip("'"),
        os.environ.get("AV_CLIENT_SECRET", "").strip().strip('"').strip("'"),
    )

def _make_client() -> httpx.Client:
    """Create an httpx.Client matching the SOC dashboard's AsyncClient settings."""
    return httpx.Client(
        verify=False,
        timeout=httpx.Timeout(60.0, connect=15.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
    )


# ─── Token cache (module-level) ───────────────────────────────────────────────

_token_cache: dict = {"token": None, "expiry": 0.0, "base_path": "/api/1.1"}


def get_token() -> str:
    """Get OAuth2 bearer token with TTL cache."""
    global _token_cache
    if _token_cache["token"] and time.time() < _token_cache["expiry"]:
        return _token_cache["token"]

    sub = _get_subdomain()
    cid, csec = _get_creds()
    base = f"https://{sub}"

    with _make_client() as client:
        for ep in ("/api/1.1/oauth/token", "/api/1.0/oauth/token", "/api/2.0/oauth/token", "/oauth/token"):
            try:
                resp = client.post(base + ep, data={"grant_type": "client_credentials"}, auth=(cid, csec))
                logger.info(f"AV auth {ep} → HTTP {resp.status_code}")
                if resp.status_code == 200:
                    body = resp.json()
                    token = body.get("access_token", "")
                    if token:
                        expires_in = int(body.get("expires_in", 3600))
                        base_path = "/api/1.1" if "1.1" in ep else "/api/2.0" if "2.0" in ep else "/api/1.1"
                        _token_cache = {
                            "token": token,
                            "expiry": time.time() + expires_in - 60,
                            "base_path": base_path,
                        }
                        logger.info(f"AV: token acquired via {ep}")
                        return token
            except Exception as e:
                logger.warning(f"AV auth {ep} → {e}")

    raise RuntimeError(f"AV: all OAuth endpoints failed for {sub}. Check AV_CLIENT_ID / AV_CLIENT_SECRET env vars.")


def _get_dep_token(dep_url: str, central_token: str) -> str:
    """
    Try to get a per-deployment token (SOC dashboard does this too).
    Falls back to central token if the deployment doesn't support its own OAuth.
    """
    cid, csec = _get_creds()
    base = dep_url.rstrip("/")
    with _make_client() as client:
        for ep in ("/api/2.0/oauth/token", "/api/1.1/oauth/token", "/api/1.0/oauth/token"):
            try:
                r = client.post(base + ep, data={"grant_type": "client_credentials"}, auth=(cid, csec))
                if r.status_code == 200:
                    t = r.json().get("access_token", "")
                    if t:
                        logger.info(f"AV: per-dep token for {dep_url} via {ep}")
                        return t
            except Exception:
                continue
    logger.info(f"AV: using central token for {dep_url}")
    return central_token


# ─── Deployment URL resolution ─────────────────────────────────────────────────

def _resolve_dep_url(dep: dict) -> str:
    """Resolve a usable HTTPS base URL from a deployment dict (same logic as SOC fetcher)."""
    for key in ("url", "fqdn", "hostname", "base_url"):
        val = dep.get(key, "")
        if val:
            return (f"https://{val}" if not val.startswith("http") else val).rstrip("/")

    self_link = (dep.get("_links") or {}).get("self", {}).get("href", "")
    if self_link and "alienvault.cloud" in self_link:
        from urllib.parse import urlparse as _up
        p = _up(self_link)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"

    dep_id = dep.get("id", "")
    if dep_id and "://" in dep_id:
        host = dep_id.split("://")[1].split("/")[0]
        if host:
            return f"https://{host}"

    name = dep.get("name", "").strip()
    if name:
        if "alienvault.cloud" in name:
            return (f"https://{name}" if not name.startswith("http") else name).rstrip("/")
        if " " not in name and not name.startswith("http"):
            # Bare name like 'etranzact2' → 'https://etranzact2.alienvault.cloud'
            return f"https://{name}.alienvault.cloud"

    return ""


# ─── Deployments ──────────────────────────────────────────────────────────────

def get_deployments() -> list[dict]:
    """Return all AV deployments with resolved _url field."""
    try:
        token = get_token()
    except RuntimeError as e:
        logger.error(f"AV get_deployments: {e}")
        return []

    sub = _get_subdomain()
    base = f"https://{sub}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base_path = _token_cache.get("base_path", "/api/1.1")

    seen: set = set()
    paths_raw = [f"{base_path}/deployments", "/api/2.0/deployments", "/api/1.1/deployments"]
    paths = [p for p in paths_raw if not (p in seen or seen.add(p))]  # type: ignore[func-returns-value]

    with _make_client() as client:
        for path in paths:
            try:
                resp = client.get(base + path, headers=headers)
                logger.info(f"AV deployments {path} → HTTP {resp.status_code}")
                if resp.status_code != 200:
                    continue
                data = resp.json()

                if "_embedded" in data:
                    emb = data["_embedded"]
                    deps = (
                        emb.get("deployments")
                        or emb.get("tenantList")
                        or emb.get("tenants")
                        or next(iter(emb.values()), [])
                    )
                elif isinstance(data, list):
                    deps = data
                else:
                    deps = data.get("deployments") or data.get("data") or []

                logger.info(f"AV: {len(deps)} deployments from {path}")
                if not deps:
                    continue

                logger.info(f"AV: first dep keys={list(deps[0].keys())}")
                for d in deps:
                    d["_url"] = _resolve_dep_url(d)
                    logger.info(f"AV dep '{d.get('name','?')}' → {d['_url']!r}")
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
    Exact sync port of SOC dashboard _fetch_alarms_one.

    Key details that make it work:
    - httpx.Client(verify=False) — SSL cert issues don't block AV deployment endpoints
    - Per-deployment token tried first (some deployments require own auth)
    - timestamp_received_gte/lte (not occured — this is what the API actually filters on)
    - status passed as list-of-tuples → sends ?status=open&status=closed&status=in_review
    - Fallback retry without status filter if HTTP != 200
    - Pagination cap: 10 pages for large datasets (>1000 alarms), 20 for small
    """
    if not dep_url:
        return []

    auth_token = _get_dep_token(dep_url, token)
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
    url = dep_url.rstrip("/") + "/api/2.0/alarms"

    # EXACT params from SOC dashboard _fetch_alarms_one
    params: dict = {
        "timestamp_received_gte": start_ms,
        "timestamp_received_lte": end_ms,
        "sort": "timestamp_received,desc",
        "suppressed": "false",
        "size": 500,
        "page": 0,
    }
    base_params = list(params.items()) + [
        ("status", "open"),
        ("status", "closed"),
        ("status", "in_review"),
    ]

    all_alarms: list[dict] = []
    total_elements = None

    with _make_client() as client:
        try:
            # Page 0
            resp = client.get(url, headers=headers, params=base_params)
            logger.info(f"AV alarms {dep_name} HTTP {resp.status_code}")

            if resp.status_code != 200:
                logger.warning(f"AV: {dep_name} HTTP {resp.status_code} — retrying without status filter")
                fallback = [(k, v) for k, v in base_params if k != "status"]
                resp = client.get(url, headers=headers, params=fallback)
                logger.info(f"AV: {dep_name} fallback HTTP {resp.status_code}")
                if resp.status_code != 200:
                    logger.warning(f"AV: {dep_name} fallback also failed — skipping")
                    return []
                base_params = fallback  # use fallback for subsequent pages too

            body = resp.json()
            page_meta = body.get("page", {})
            total_elements = (
                page_meta.get("totalElements")
                or body.get("total_elements")
                or body.get("total")
            )
            total_pages = (
                page_meta.get("totalPages")
                or body.get("total_pages")
                or body.get("totalPages")
            )
            logger.info(
                f"AV: {dep_name} page_meta={page_meta} total_elements={total_elements} total_pages={total_pages}"
            )

            batch = body.get("_embedded", {}).get("alarms", [])
            for a in batch:
                a["_deployment_name"] = dep_name
            all_alarms.extend(batch)

            # Pagination cap matching SOC dashboard
            large_dataset = total_elements and int(total_elements) > 1000
            max_pages = 10 if large_dataset else 20
            page_num = 1

            while batch and page_num < max_pages and len(all_alarms) < max_records:
                try:
                    page_params = [(k, v) for k, v in base_params if k != "page"] + [("page", str(page_num))]
                    r = client.get(url, headers=headers, params=page_params)
                    if r.status_code != 200:
                        break
                    batch = r.json().get("_embedded", {}).get("alarms", [])
                    for a in batch:
                        a["_deployment_name"] = dep_name
                    all_alarms.extend(batch)
                    logger.debug(f"AV: {dep_name} page {page_num} → {len(batch)} alarms")
                    page_num += 1
                except Exception as pe:
                    logger.warning(f"AV: {dep_name} page {page_num} error: {pe}")
                    break

        except Exception as e:
            logger.error(f"AV alarm fetch {dep_name}: {e}")

    if all_alarms and total_elements:
        all_alarms[0]["_total_elements"] = int(total_elements)
    logger.info(f"AV: {dep_name} → {len(all_alarms)} alarms (API total: {total_elements})")
    return all_alarms[:max_records]


def fetch_events_for_deployment(
    dep_url: str,
    token: str,
    start_ms: int,
    end_ms: int,
    dep_name: str = "",
    max_records: int = 5000,
) -> list[dict]:
    """Fetch events from one deployment — mirrors alarm fetch pattern."""
    if not dep_url:
        return []

    auth_token = _get_dep_token(dep_url, token)
    headers = {"Authorization": f"Bearer {auth_token}", "Content-Type": "application/json"}
    url = dep_url.rstrip("/") + "/api/2.0/events"

    base_params = [
        ("timestamp_received_gte", start_ms),
        ("timestamp_received_lte", end_ms),
        ("sort", "timestamp_received,desc"),
        ("size", 500),
        ("page", 0),
    ]
    all_events: list[dict] = []

    with _make_client() as client:
        try:
            resp = client.get(url, headers=headers, params=base_params)
            logger.info(f"AV events {dep_name} HTTP {resp.status_code}")
            if resp.status_code != 200:
                return []

            body = resp.json()
            emb = body.get("_embedded", {})
            batch = (
                emb.get("events")
                or emb.get("eventResourceList")
                or emb.get("eventResources")
                or []
            )
            for e in batch:
                e["_deployment_name"] = dep_name
            all_events.extend(batch)

            page_meta = body.get("page", {})
            total_pages = page_meta.get("totalPages", 1)
            page_num = 1

            while batch and page_num < min(total_pages, 10) and len(all_events) < max_records:
                try:
                    pp = [(k, v) for k, v in base_params if k != "page"] + [("page", str(page_num))]
                    r = client.get(url, headers=headers, params=pp)
                    if r.status_code != 200:
                        break
                    emb2 = r.json().get("_embedded", {})
                    batch = (
                        emb2.get("events")
                        or emb2.get("eventResourceList")
                        or emb2.get("eventResources")
                        or []
                    )
                    for e in batch:
                        e["_deployment_name"] = dep_name
                    all_events.extend(batch)
                    page_num += 1
                except Exception:
                    break

        except Exception as e:
            logger.error(f"AV events {dep_name}: {e}")

    logger.info(f"AV: {dep_name} → {len(all_events)} events")
    return all_events[:max_records]


# ─── Multi-deployment parallel fetch ──────────────────────────────────────────

def fetch_all_deployments(
    token: str,
    start_ms: int,
    end_ms: int,
    max_workers: int = 4,
) -> tuple[list[dict], list[dict]]:
    """Fetch alarms+events from ALL resolvable deployments in parallel (max_workers=4)."""
    deps = get_deployments()
    if not deps:
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
        return a, e

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_fetch_one, d): d for d in deps}
        for fut in as_completed(futures):
            try:
                a, e = fut.result()
                all_alarms.extend(a)
                all_events.extend(e)
            except Exception as err:
                dep = futures[fut]
                logger.error(f"AV: {dep.get('name')} gather error: {err}")

    logger.info(f"AV fetch_all_deployments: {len(all_alarms)} alarms, {len(all_events)} events")
    return all_alarms, all_events


# ─── Data processing ──────────────────────────────────────────────────────────

def _safe_vc(series, name_col, count_col, top=30):
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
        "User Account was Unlocked", "A User Account was Disabled",
        "User added to Admin role", "User Added to Enterprise Admins Group",
        "Create User", "User Added to Local Administrators Group",
    ]
    user_activities = [{"Activity": k, "Count": int((m == k).sum())} for k in user_act_keys]

    unlocked_users: list = []
    disabled_users: list = []
    if "source_username" in df.columns:
        unlocked_users = _safe_vc(
            df.loc[m == "User Account was Unlocked", "source_username"], "Username", "Count"
        )
        disabled_users = _safe_vc(
            df.loc[m == "A User Account was Disabled", "source_username"], "Username", "Count"
        )

    return {
        "top_methods": top_methods, "top_strategy": top_strategy,
        "top_intent": top_intent, "failed_logons": failed_logons,
        "user_activities": user_activities, "unlocked_users": unlocked_users,
        "disabled_users": disabled_users, "severity": severity,
    }


def process_events(events: list) -> dict:
    if not events:
        return {}
    df = pd.json_normalize(events)

    sensor_field = next(
        (f for f in ["sensor", "data_source", "source_name", "plugin", "sensor_name"] if f in df.columns),
        None,
    )
    sensor_list, top_event_names, events_by_sensor = [], [], {}

    if sensor_field:
        sensors = df[sensor_field].dropna().unique().tolist()
        sensor_list = [{"Sensor Name": s} for s in sensors]
        if "event_name" in df.columns:
            top_event_names = _safe_vc(df["event_name"], "Event Name", "Count", top=20)
            for sensor in sensors:
                ev = _safe_vc(
                    df.loc[df[sensor_field] == sensor, "event_name"], "Event Name", "Count", top=20
                )
                events_by_sensor[str(sensor)] = ev
    elif "event_name" in df.columns:
        top_event_names = _safe_vc(df["event_name"], "Event Name", "Count", top=20)

    return {
        "sensor_list": sensor_list,
        "top_event_names": top_event_names,
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
