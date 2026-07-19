"""
SentinelOne Exclusive — Backend Logic
Same structure as sentinel_nfr but targets the Exclusive environment.
Credentials are read fresh per-call (never cached at import time).
"""
import requests, re, time
import pandas as pd
from io import BytesIO
from datetime import datetime
from collections import Counter
import logging
import os

from apps.sentinel_nfr.logic import (
    process_agent_stats, process_vulnerabilities,
    _normalize_severity, build_site_summary, export_site_to_excel,
)

logger = logging.getLogger("sentinel_excl.logic")

# ── Credentials: read fresh per-call (never cached at import time) ────────────
def _get_base_url() -> str:
    url = os.environ.get(
        "S1_EXCL_BASE_URL",
        "https://euce1-exclusive.sentinelone.net/web/api/v2.1"
    ).rstrip("/")
    # Auto-append the API path if only the hostname was set in Railway
    if "/web/api/" not in url and "/api/v" not in url:
        url = url + "/web/api/v2.1"
        logger.info(f"S1 Excl: base URL normalised to {url}")
    return url

def _get_headers() -> dict:
    token = os.environ.get("S1_EXCL_TOKEN", "")
    if not token:
        logger.error("S1_EXCL_TOKEN env var is NOT set — all API calls will return 401")
    return {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}


# ── Core paginated fetcher ────────────────────────────────────────────────────

def fetch_all_with_cursor(endpoint, params=None, timeout=30):
    if params is None: params = {}
    all_items, cursor = [], None
    base_url = _get_base_url()
    headers  = _get_headers()
    url      = f"{base_url}/{endpoint.lstrip('/')}"
    p        = params.copy()
    logger.info(f"S1 Excl: GET {url} params={list(p.keys())}")
    while True:
        if cursor: p["cursor"] = cursor
        try:
            resp = requests.get(url, headers=headers, params=p, timeout=timeout)
        except Exception as e:
            logger.error(f"S1 Excl network error {endpoint}: {e}")
            raise RuntimeError(f"Network error: {e}")
        if resp.status_code == 401:
            logger.error(
                f"S1 Excl 401 Unauthorized on {endpoint} — "
                "check S1_EXCL_TOKEN in Railway environment variables"
            )
            raise RuntimeError("Auth failed (401)")
        if resp.status_code != 200:
            logger.error(f"S1 Excl {endpoint} HTTP {resp.status_code}: {resp.text[:300]}")
            raise RuntimeError(f"HTTP {resp.status_code}")
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
        sites = fetch_all_with_cursor("sites", {"limit": 200})
        logger.info(f"S1 Excl: {len(sites)} sites returned")
        return sites if isinstance(sites, list) else []
    except Exception as e:
        logger.error(f"S1 Excl fetch_sites failed: {e}")
        return []


def fetch_endpoints_for_site(site_id):
    try:
        return fetch_all_with_cursor("agents", {"siteIds": site_id, "limit": 1000})
    except Exception as e:
        logger.error(f"S1 Excl fetch_endpoints_for_site({site_id}) failed: {e}")
        return []


def fetch_threats_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("threats", {
            "siteIds": site_id, "createdAt__gte": start_iso,
            "createdAt__lte": end_iso, "limit": 1000,
            "sortBy": "createdAt", "sortOrder": "desc"})
    except Exception as e:
        logger.error(f"S1 Excl fetch_threats_for_site({site_id}) failed: {e}")
        return []


def fetch_risks_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("application-management/risks", {
            "siteIds": site_id, "detectionDate__gte": start_iso,
            "detectionDate__lte": end_iso, "limit": 1000,
            "sortBy": "detectionDate", "sortOrder": "desc"})
    except Exception as e:
        logger.error(f"S1 Excl fetch_risks_for_site({site_id}) failed: {e}")
        return []


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
            valid_sids = []
            for s in (raw_sids if isinstance(raw_sids, list) else []):
                valid_sids.append(str(s.get("id")) if isinstance(s, dict) else str(s))
            if str(site_id) in valid_sids:
                rows.append({"Hash Value": sha256, "OS Type": item.get("osType", "Unknown")})
        df_h = pd.DataFrame(rows, columns=["Hash Value", "OS Type"])
        if df_h.empty:
            return df_h, pd.DataFrame(columns=["OS Type", "Count"])
        df_s = df_h.groupby("OS Type").size().reset_index(name="Count")
        df_s.loc[len(df_s)] = ["Total", len(df_h)]
        return df_h, df_s
    except Exception as e:
        logger.error(f"S1 Excl fetch_blocklisted_hashes_for_site({site_id}) failed: {e}")
        return (pd.DataFrame(columns=["Hash Value", "OS Type"]),
                pd.DataFrame(columns=["OS Type", "Count"]))
