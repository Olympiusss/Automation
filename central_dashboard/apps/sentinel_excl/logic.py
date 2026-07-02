"""
SentinelOne Exclusive — Backend Logic
Same structure as sentinel_nfr but targets the Exclusive environment.
"""
import requests, re, time
import pandas as pd
from io import BytesIO
from datetime import datetime
from collections import Counter
from apps.sentinel_nfr.logic import (
    process_agent_stats, process_vulnerabilities,
    _normalize_severity, build_site_summary, export_site_to_excel,
)

import os

BASE_URL  = os.environ.get("S1_EXCL_BASE_URL", "https://euce1-exclusive.sentinelone.net/web/api/v2.1")
API_TOKEN = os.environ.get("S1_EXCL_TOKEN", "")
HEADERS   = {"Authorization": f"ApiToken {API_TOKEN}", "Content-Type": "application/json"}

# Site PINs removed — no longer used per security policy


def fetch_all_with_cursor(endpoint, params=None, timeout=30):
    if params is None: params = {}
    all_items, cursor = [], None
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    p = params.copy()
    while True:
        if cursor: p["cursor"] = cursor
        try:
            resp = requests.get(url, headers=HEADERS, params=p, timeout=timeout)
        except Exception as e:
            raise RuntimeError(f"Network error: {e}")
        if resp.status_code == 401: raise RuntimeError("Auth failed (401)")
        if resp.status_code != 200: raise RuntimeError(f"HTTP {resp.status_code}")
        body  = resp.json()
        items = body.get("data", body)
        if isinstance(items, dict) and "sites" in items: items = items["sites"]
        if isinstance(items, list): all_items.extend(items)
        cursor = (body.get("pagination") or {}).get("nextCursor")
        if not cursor: break
        time.sleep(0.05)
    return all_items


def fetch_sites():
    try:
        s = fetch_all_with_cursor("sites", {"limit": 200})
        return s if isinstance(s, list) else []
    except: return []


def fetch_endpoints_for_site(site_id):
    try: return fetch_all_with_cursor("agents", {"siteIds": site_id, "limit": 1000})
    except: return []


def fetch_threats_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("threats", {
            "siteIds": site_id, "createdAt__gte": start_iso,
            "createdAt__lte": end_iso, "limit": 1000,
            "sortBy": "createdAt", "sortOrder": "desc"})
    except: return []


def fetch_risks_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("application-management/risks", {
            "siteIds": site_id, "detectionDate__gte": start_iso,
            "detectionDate__lte": end_iso, "limit": 1000,
            "sortBy": "detectionDate", "sortOrder": "desc"})
    except: return []


def fetch_blocklisted_hashes_for_site(site_id):
    try:
        data = fetch_all_with_cursor("restrictions", {"limit": 1000, "siteIds": site_id})
        rows = []
        for item in data:
            if not isinstance(item, dict): continue
            sha256 = item.get("sha256Value")
            if not sha256: continue
            scope     = item.get("scope", {})
            raw_sids  = scope.get("siteIds", [])
            valid_sids= []
            for s in (raw_sids if isinstance(raw_sids, list) else []):
                valid_sids.append(str(s.get("id")) if isinstance(s, dict) else str(s))
            if str(site_id) in valid_sids:
                rows.append({"Hash Value": sha256, "OS Type": item.get("osType","Unknown")})
        df_h = pd.DataFrame(rows, columns=["Hash Value","OS Type"])
        if df_h.empty:
            return df_h, pd.DataFrame(columns=["OS Type","Count"])
        df_s = df_h.groupby("OS Type").size().reset_index(name="Count")
        df_s.loc[len(df_s)] = ["Total", len(df_h)]
        return df_h, df_s
    except:
        return pd.DataFrame(columns=["Hash Value","OS Type"]), pd.DataFrame(columns=["OS Type","Count"])
