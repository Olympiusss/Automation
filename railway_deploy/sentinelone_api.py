"""
SentinelOne API Client — Lightweight module for direct API access.
No Streamlit UI dependencies. Used by the AI agent tools.
"""

import streamlit as st
import requests
import pandas as pd
import re
import time
from datetime import datetime, timezone
from collections import Counter
from typing import Optional


# --------------------
# CONFIG (from Streamlit secrets)
# --------------------
BASE_URL = "https://euce1-exclusive.sentinelone.net/web/api/v2.1"

def _get_headers():
    """Get API headers with token from secrets or env vars (lazy load)."""
    import os
    token = ""
    try:
        token = st.secrets.get("general", {}).get("api_token", "")
    except Exception:
        pass
    
    if not token:
        token = os.environ.get("S1_API_TOKEN", os.environ.get("API_TOKEN", ""))
        
    return {
        "Authorization": f"ApiToken {token}",
        "Content-Type": "application/json"
    }


# --------------------
# Cursor Pagination
# --------------------
def fetch_all_with_cursor(endpoint, params=None, timeout=30):
    """Fetch all pages of data from a paginated SentinelOne API endpoint."""
    if params is None:
        params = {}
    all_items = []
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    cursor = None
    params = params.copy()
    headers = _get_headers()
    while True:
        if cursor:
            params["cursor"] = cursor
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=timeout)
        except Exception as e:
            raise RuntimeError(f"Network error fetching {endpoint}: {e}")
        if resp.status_code == 401:
            raise RuntimeError(f"Authentication failed when fetching {endpoint}: 401")
        if resp.status_code != 200:
            raise RuntimeError(f"Failed to fetch {endpoint}: {resp.status_code} {resp.text}")
        body = resp.json()
        items = body.get("data", body)
        if isinstance(items, dict) and "sites" in items:
            items = items["sites"]
        if isinstance(items, list):
            all_items.extend(items)
        pagination = body.get("pagination", {}) or {}
        cursor = pagination.get("nextCursor")
        if not cursor:
            break
        time.sleep(0.05)
    return all_items


# --------------------
# Fetch Functions
# --------------------
def fetch_sites():
    """Fetch all available sites."""
    try:
        sites = fetch_all_with_cursor("sites", {"limit": 200})
        if not isinstance(sites, list):
            sites = []
        return sites
    except Exception:
        return []


def fetch_endpoints_for_site(site_id):
    """Fetch all endpoints/agents for a site."""
    try:
        return fetch_all_with_cursor("agents", {"siteIds": site_id, "limit": 1000})
    except Exception:
        return []


def fetch_threats_for_site(site_id, start_iso=None, end_iso=None):
    """Fetch threats for a site within a date range."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 1000,
            "sortBy": "createdAt",
            "sortOrder": "desc"
        }
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        return fetch_all_with_cursor("threats", params)
    except Exception:
        return []


def fetch_risks_for_site(site_id, start_iso=None, end_iso=None):
    """Fetch vulnerability/risk data for a site."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 1000,
            "sortBy": "detectionDate",
            "sortOrder": "desc"
        }
        if start_iso:
            params["detectionDate__gte"] = start_iso
        if end_iso:
            params["detectionDate__lte"] = end_iso
        return fetch_all_with_cursor("application-management/risks", params)
    except Exception:
        return []


def fetch_alerts_for_site(site_id, start_iso=None, end_iso=None, severity=None):
    """Fetch cloud detection alerts for a site."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 1000,
            "sortBy": "createdAt",
            "sortOrder": "desc"
        }
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        if severity:
            params["severity"] = severity
        return fetch_all_with_cursor("cloud-detection/alerts", params)
    except Exception:
        return []


def fetch_activities_for_site(site_id, start_iso=None, end_iso=None, activity_types=None):
    """Fetch activity/audit trail for a site."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 1000,
            "sortBy": "createdAt",
            "sortOrder": "desc"
        }
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        if activity_types:
            params["activityTypes"] = activity_types
        return fetch_all_with_cursor("activities", params)
    except Exception:
        return []


def fetch_threat_details(threat_id):
    """Fetch detailed forensic data for a single threat by ID."""
    try:
        url = f"{BASE_URL}/threats/{threat_id}"
        headers = _get_headers()
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            body = resp.json()
            return body.get("data", body)
        return None
    except Exception:
        return None


def fetch_deep_visibility_events(query_filter, site_id=None, from_date=None, to_date=None, limit=100):
    """
    Query Deep Visibility events.
    query_filter: DV query string, e.g. 'ObjectType = "process" AND TrueContext = "malicious"'
    """
    try:
        headers = _get_headers()
        # Step 1: Create a DV query
        query_payload = {
            "query": query_filter,
            "fromDate": from_date or "",
            "toDate": to_date or "",
            "limit": min(limit, 1000),
        }
        if site_id:
            query_payload["siteIds"] = [site_id]

        create_resp = requests.post(
            f"{BASE_URL}/dv/init-query",
            headers=headers,
            json=query_payload,
            timeout=30
        )
        if create_resp.status_code != 200:
            return []

        query_id = create_resp.json().get("data", {}).get("queryId")
        if not query_id:
            return []

        # Step 2: Poll for results (DV queries are async)
        for _ in range(15):
            time.sleep(2)
            status_resp = requests.get(
                f"{BASE_URL}/dv/query-status",
                headers=headers,
                params={"queryId": query_id},
                timeout=30
            )
            if status_resp.status_code == 200:
                status_data = status_resp.json().get("data", {})
                if status_data.get("responseState") == "FINISHED":
                    break
                if status_data.get("responseState") == "FAILED":
                    return []

        # Step 3: Fetch events
        events_resp = requests.get(
            f"{BASE_URL}/dv/events",
            headers=headers,
            params={"queryId": query_id, "limit": limit},
            timeout=30
        )
        if events_resp.status_code == 200:
            return events_resp.json().get("data", [])
        return []
    except Exception:
        return []


def fetch_exclusions_for_site(site_id):
    """Fetch exclusion/whitelist rules for a site."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 1000
        }
        return fetch_all_with_cursor("exclusions", params)
    except Exception:
        return []


def fetch_policies_for_site(site_id):
    """Fetch active policies for a site."""
    try:
        params = {
            "siteIds": site_id,
            "limit": 200
        }
        return fetch_all_with_cursor("private/policies", params)
    except Exception:
        return []


def fetch_blocklisted_hashes_for_site(site_id, start_iso=None, end_iso=None):
    """
    Fetch blocklisted hashes (restrictions) for a specific site.
    Returns (df_hashes, df_summary) DataFrames.
    """
    try:
        params = {
            "limit": 1000,
            "type": "black_hash",
            "siteIds": site_id,
            "includeParents": "true",
            "includeChildren": "true"
        }
        all_data = fetch_all_with_cursor("restrictions", params)

        # Parse date range for client-side filtering
        start_dt, end_dt = None, None
        if start_iso:
            try:
                start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
            except Exception:
                pass
        if end_iso:
            try:
                end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            except Exception:
                pass

        rows = []
        for item in all_data:
            if not isinstance(item, dict):
                continue
            sha256 = item.get("sha256Value") or item.get("value")
            if not sha256:
                continue

            updated_at_str = item.get("updatedAt", "")

            # Client-side date filtering
            if start_dt or end_dt:
                if updated_at_str:
                    try:
                        updated_dt = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                        if start_dt and updated_dt < start_dt:
                            continue
                        if end_dt and updated_dt > end_dt:
                            continue
                    except Exception:
                        pass

            rows.append({
                "Hash Value": sha256,
                "OS Type": item.get("osType", "Unknown"),
                "Description": item.get("description", ""),
                "Source": item.get("source", "Unknown"),
                "Last Updated": updated_at_str,
                "Created At": item.get("createdAt", ""),
                "Scope": item.get("scopeName", ""),
                "User": item.get("userName", ""),
                "Imported": "Yes" if item.get("imported", False) else "No",
                "Not Recommended": item.get("notRecommended", "") or "N/A"
            })

        df_hashes = pd.DataFrame(rows)

        empty_cols = [
            "Hash Value", "OS Type", "Description", "Source",
            "Last Updated", "Created At", "Scope", "User", "Imported", "Not Recommended"
        ]
        if df_hashes.empty:
            return (
                pd.DataFrame(columns=empty_cols),
                pd.DataFrame(columns=["OS Type", "Count"])
            )

        # OS distribution summary
        df_hash_summary = (
            df_hashes.groupby("OS Type").size().reset_index(name="Count")
        )
        df_hash_summary.loc[len(df_hash_summary.index)] = ["Total", len(df_hashes)]
        return df_hashes, df_hash_summary

    except Exception:
        return (
            pd.DataFrame(columns=[
                "Hash Value", "OS Type", "Description", "Source",
                "Last Updated", "Created At", "Scope", "User", "Imported", "Not Recommended"
            ]),
            pd.DataFrame(columns=["OS Type", "Count"])
        )


# --------------------
# Data Processing
# --------------------
def _normalize_severity(raw_sev, base_score=None, nvd_score=None):
    """Normalize severity strings/scores into standard categories."""
    if raw_sev and isinstance(raw_sev, str):
        s = raw_sev.strip()
        m = re.match(
            r"(?i)^(critical|crit|high|medium|med|low|info|informational|none|false positive|false_positive|false|unknown)\b", s
        )
        if m:
            token = m.group(1).lower()
            if token in ("crit", "critical"): return "Critical"
            if token == "high": return "High"
            if token in ("medium", "med"): return "Medium"
            if token == "low": return "Low"
            if token in ("info", "informational"): return "Informational"
            if token in ("false positive", "false_positive", "false"): return "False Positive"
            if token == "none": return "None"
            if token == "unknown": return "Unknown"
        if "critical" in s.lower(): return "Critical"
        if "high" in s.lower(): return "High"
        if "medium" in s.lower(): return "Medium"
        if "low" in s.lower(): return "Low"
        if "false" in s.lower(): return "False Positive"
        return s.title()

    score = None
    for v in (nvd_score, base_score):
        try:
            if v is None: continue
            score = float(v)
            break
        except Exception:
            continue
    if score is not None:
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        if score > 0.0: return "Low"
        return "None"
    return "Unknown"


def process_vulnerabilities(risks):
    """Process raw vulnerability data into structured DataFrames."""
    app_versions, endpoints, severities = [], [], []
    for r in risks:
        app_name = r.get("applicationName") or r.get("application") or r.get("appName")
        app_ver = r.get("applicationVersion") or r.get("application_version") or r.get("version")
        if app_name:
            if app_ver:
                app_versions.append(f"{app_name} {app_ver}")
            else:
                app_versions.append(app_name)
        ep = r.get("endpointName") or r.get("endpoint")
        if ep:
            endpoints.append(ep)
        raw_sev = r.get("severity")
        nvd_score = r.get("nvdBaseScore") or r.get("nvdCvssVersion")
        base_score = r.get("baseScore") or r.get("riskScore")
        normalized = _normalize_severity(raw_sev, base_score=base_score, nvd_score=nvd_score)
        if normalized:
            severities.append(normalized)

    df_app_versions = pd.DataFrame(Counter(app_versions).most_common(50), columns=["Application + Version", "Count"])
    df_app_versions.loc[len(df_app_versions.index)] = ["Total Occurrences", sum(Counter(app_versions).values())]

    df_endpoints = pd.DataFrame(Counter(endpoints).most_common(50), columns=["Endpoint Name", "Count"])
    df_endpoints.loc[len(df_endpoints.index)] = ["Total Occurrences", sum(Counter(endpoints).values())]

    df_severity = pd.DataFrame(Counter(severities).most_common(50), columns=["Severity", "Count"])
    df_severity.loc[len(df_severity.index)] = ["Total Occurrences", sum(Counter(severities).values())]

    unique_vuln_endpoints = len(set(endpoints))

    details_rows = []
    for r in risks:
        app_name = r.get("applicationName") or r.get("application") or r.get("appName")
        app_ver = r.get("applicationVersion") or r.get("application_version") or r.get("version")
        ep = r.get("endpointName") or r.get("endpoint")
        raw_sev = r.get("severity")
        nvd_score = r.get("nvdBaseScore") or r.get("nvdCvssVersion")
        base_score = r.get("baseScore") or r.get("riskScore")
        normalized = _normalize_severity(raw_sev, base_score=base_score, nvd_score=nvd_score)
        if app_name and ep:
            details_rows.append({
                "Application": app_name,
                "Version": app_ver if app_ver else "N/A",
                "Endpoint Name": ep,
                "Severity": normalized if normalized else "Unknown"
            })

    df_vuln_details = pd.DataFrame(details_rows, columns=["Application", "Version", "Endpoint Name", "Severity"])
    if not df_vuln_details.empty:
        df_vuln_details = df_vuln_details.sort_values(by=["Application", "Endpoint Name"])

    return df_vuln_details, df_app_versions, df_endpoints, df_severity, unique_vuln_endpoints


def process_agent_stats(endpoints):
    """Process endpoint data into agent health statistics."""
    versions = [e.get("agentVersion", "Unknown") for e in endpoints]
    versions = [v for v in versions if v]

    df_versions = pd.DataFrame(Counter(versions).most_common(20), columns=["Agent Version", "Count"])

    attention_counts = Counter()
    for e in endpoints:
        missing_perms = e.get("missingPermissions")
        if missing_perms:
            attention_counts["Missing permission"] += 1
            continue
        ua = e.get("userActionsNeeded")
        if ua == "incompatible_os":
            attention_counts["Incompatible OS"] += 1
            continue
        if ua == "unprotected" or e.get("isProtected") is False:
            attention_counts["Unprotected"] += 1
            continue
        op_state = e.get("operationalState")
        if op_state == "shunned" or op_state == "disabled":
            attention_counts["Agent suppressed"] += 1
            continue
        if ua and ua not in ["none", "incompatible_os", "unprotected"]:
            attention_counts["Attention needed"] += 1
            continue

    df_attention = pd.DataFrame(attention_counts.items(), columns=["Category", "Count"])
    return df_versions, df_attention
