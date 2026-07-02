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
SUBDOMAIN     = os.environ.get("AV_SUBDOMAIN", "cybervergent-nfr.alienvault.cloud")
CLIENT_ID     = os.environ.get("AV_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("AV_CLIENT_SECRET", "")


def get_token(subdomain: str | None = None, client_id: str | None = None, client_secret: str | None = None) -> str:
    _sub = subdomain or SUBDOMAIN
    _id  = client_id  or CLIENT_ID
    _sec = client_secret or CLIENT_SECRET
    url  = f"https://{_sub}/api/2.0/oauth/token"
    resp = requests.post(url, data={"grant_type": "client_credentials"},
                         auth=(_id, _sec), timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def get_deployments() -> list[dict]:
    """
    Return all AV deployments visible to the central account.
    Each dict has: name, displayName, _url (the deployment's own API base URL).
    """
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"https://{SUBDOMAIN}"
    for path in ["/api/2.0/deployments", "/api/1.1/deployments", "/deployments"]:
        try:
            resp = requests.get(base + path, headers=headers, timeout=30)
            if resp.status_code != 200:
                continue
            data = resp.json()
            if "_embedded" in data:
                embedded = data["_embedded"]
                deps = (
                    embedded.get("deployments")
                    or embedded.get("tenantList")
                    or embedded.get("tenants")
                    or next(iter(embedded.values()), [])
                )
            elif isinstance(data, list):
                deps = data
            else:
                deps = data.get("deployments", [])
            if deps:
                # Resolve each deployment's own URL
                for d in deps:
                    for field in ["url", "domain", "apiUrl", "baseUrl", "hostname"]:
                        raw = d.get(field, "")
                        if raw:
                            if not raw.startswith("http"):
                                raw = "https://" + raw
                            d["_url"] = raw.rstrip("/")
                            break
                    else:
                        d["_url"] = ""
                return deps
        except Exception:
            pass
    return []


def fetch_alarms_for_deployment(dep_url: str, token: str, start_ms: int, end_ms: int, max_records: int = 5000) -> list:
    """Fetch alarms from a specific deployment URL (per-client fetch)."""
    if not dep_url:
        return []
    url = dep_url.rstrip("/") + "/api/2.0/alarms"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base_params = {
        "timestamp_received_gte": start_ms,
        "timestamp_received_lte": end_ms,
        "sort": "timestamp_received,desc",
        "suppressed": "false",
        "size": 500,
        "status": ["open", "closed", "in_review"],
    }
    all_alarms = []
    for page in range(20):  # up to 10,000 alarms per deployment
        try:
            p = {**base_params, "page": page}
            resp = requests.get(url, headers=headers, params=p, timeout=45)
            if resp.status_code != 200:
                break
            batch = resp.json().get("_embedded", {}).get("alarms", [])
            if not batch:
                break
            all_alarms.extend(batch)
            if len(batch) < 500 or len(all_alarms) >= max_records:
                break
        except Exception:
            break
    return all_alarms[:max_records]


def fetch_events_for_deployment(dep_url: str, token: str, start_ms: int, end_ms: int, max_records: int = 5000) -> list:
    """Fetch events from a specific deployment URL."""
    if not dep_url:
        return []
    url = dep_url.rstrip("/") + "/api/2.0/events"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    all_events = []
    for page in range(20):
        try:
            resp = requests.get(url, headers=headers, params={
                "timestamp_received_gte": start_ms,
                "timestamp_received_lte": end_ms,
                "sort": "timestamp_received,desc",
                "size": 500,
                "page": page,
            }, timeout=45)
            if resp.status_code != 200:
                break
            batch = resp.json().get("_embedded", {}).get("eventResources", [])
            if not batch:
                break
            all_events.extend(batch)
            if len(batch) < 500 or len(all_events) >= max_records:
                break
        except Exception:
            break
    return all_events[:max_records]


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


def fetch_all_parallel(endpoint, params, headers, max_records=20000) -> list:
    response_key_map = {"events": "eventResources", "alarms": "alarms"}
    response_key = response_key_map.get(endpoint, endpoint)

    p = params.copy()
    p["size"] = 5000
    p["page"] = 0

    url = f"https://{SUBDOMAIN}/api/2.0/{endpoint}"
    r = requests.get(url, headers=headers, params=p, timeout=60)
    if r.status_code != 200:
        return []

    data       = r.json()
    page_info  = data.get("page", {})
    total_el   = page_info.get("totalElements", 0)
    total_pg   = page_info.get("totalPages", 0)
    all_data   = data.get("_embedded", {}).get(response_key, [])

    if total_el == 0:
        return []

    max_pages = min(total_pg, (max_records // 5000) + 1, 200)
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

    return all_data[:max_records]


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
