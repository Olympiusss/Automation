"""
SentinelOne NFR — Backend Logic
Ported from sentinel.py (Streamlit) to plain Python for Flask.
"""
import requests, re, time
import pandas as pd
from io import BytesIO
from datetime import datetime, timezone
from collections import Counter
import logging
import os

logger = logging.getLogger("sentinel_nfr.logic")

# ── Credentials: read fresh per-call (never cached at import time) ────────────
def _get_base_url() -> str:
    return os.environ.get(
        "S1_NFR_BASE_URL",
        "https://euce1-110-nfr.sentinelone.net/web/api/v2.1"
    ).rstrip("/")

def _get_headers() -> dict:
    token = os.environ.get("S1_NFR_TOKEN", "")
    if not token:
        logger.error("S1_NFR_TOKEN env var is NOT set — all API calls will return 401")
    return {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}


# ── Core paginated fetcher ────────────────────────────────────────────────────

def fetch_all_with_cursor(endpoint, params=None, timeout=30):
    if params is None: params = {}
    all_items = []
    base_url  = _get_base_url()
    headers   = _get_headers()
    url       = f"{base_url}/{endpoint.lstrip('/')}"
    cursor    = None
    p         = params.copy()
    logger.info(f"S1 NFR: GET {url} params={list(p.keys())}")
    while True:
        if cursor: p["cursor"] = cursor
        try:
            resp = requests.get(url, headers=headers, params=p, timeout=timeout)
        except Exception as e:
            logger.error(f"S1 NFR network error {endpoint}: {e}")
            raise RuntimeError(f"Network error fetching {endpoint}: {e}")
        if resp.status_code == 401:
            logger.error(
                f"S1 NFR 401 Unauthorized on {endpoint} — "
                "check S1_NFR_TOKEN in Railway environment variables"
            )
            raise RuntimeError(f"Auth failed (401): {endpoint}")
        if resp.status_code != 200:
            logger.error(f"S1 NFR {endpoint} HTTP {resp.status_code}: {resp.text[:300]}")
            raise RuntimeError(f"Failed {endpoint}: {resp.status_code}")
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
        logger.info(f"S1 NFR: {len(sites)} sites returned")
        return sites if isinstance(sites, list) else []
    except Exception as e:
        logger.error(f"S1 NFR fetch_sites failed: {e}")
        return []


def fetch_endpoints_for_site(site_id):
    try: return fetch_all_with_cursor("agents", {"siteIds": site_id, "limit": 1000})
    except Exception as e:
        logger.error(f"S1 NFR fetch_endpoints_for_site({site_id}) failed: {e}")
        return []


def fetch_threats_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("threats", {
            "siteIds": site_id, "createdAt__gte": start_iso,
            "createdAt__lte": end_iso, "limit": 1000,
            "sortBy": "createdAt", "sortOrder": "desc"})
    except Exception as e:
        logger.error(f"S1 NFR fetch_threats_for_site({site_id}) failed: {e}")
        return []


def fetch_risks_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("application-management/risks", {
            "siteIds": site_id, "detectionDate__gte": start_iso,
            "detectionDate__lte": end_iso, "limit": 1000,
            "sortBy": "detectionDate", "sortOrder": "desc"})
    except Exception as e:
        logger.error(f"S1 NFR fetch_risks_for_site({site_id}) failed: {e}")
        return []


def fetch_blocklisted_hashes_for_site(site_id):
    try:
        data = fetch_all_with_cursor("restrictions", {"limit": 1000, "siteIds": site_id})
        rows = []
        for item in data:
            if not isinstance(item, dict): continue
            sha256 = item.get("sha256Value")
            if not sha256: continue
            scope = item.get("scope", {})
            raw_sids = scope.get("siteIds", [])
            valid_sids = []
            for s in (raw_sids if isinstance(raw_sids, list) else []):
                valid_sids.append(str(s.get("id")) if isinstance(s, dict) else str(s))
            if str(site_id) in valid_sids:
                rows.append({"Hash Value": sha256, "OS Type": item.get("osType", "Unknown")})
        df_h = pd.DataFrame(rows, columns=["Hash Value","OS Type"])
        if df_h.empty:
            return df_h, pd.DataFrame(columns=["OS Type","Count"])
        df_s = df_h.groupby("OS Type").size().reset_index(name="Count")
        df_s.loc[len(df_s)] = ["Total", len(df_h)]
        return df_h, df_s
    except Exception as e:
        logger.error(f"S1 NFR fetch_blocklisted_hashes_for_site({site_id}) failed: {e}")
        return pd.DataFrame(columns=["Hash Value","OS Type"]), pd.DataFrame(columns=["OS Type","Count"])


# ── Data processing helpers ───────────────────────────────────────────────────

def _normalize_severity(raw_sev, base_score=None, nvd_score=None):
    if raw_sev and isinstance(raw_sev, str):
        s = raw_sev.strip()
        m = re.match(r"(?i)^(critical|crit|high|medium|med|low|info|informational|none|false.positive|unknown)\b", s)
        if m:
            t = m.group(1).lower()
            if t in ("crit","critical"): return "Critical"
            if t == "high": return "High"
            if t in ("medium","med"): return "Medium"
            if t == "low": return "Low"
            if t in ("info","informational"): return "Informational"
            if "false" in t: return "False Positive"
            if t == "none": return "None"
            return "Unknown"
        for word, level in [("critical","Critical"),("high","High"),("medium","Medium"),("low","Low"),("false","False Positive")]:
            if word in s.lower(): return level
        return s.title()
    for v in (nvd_score, base_score):
        try:
            score = float(v)
            if score >= 9.0: return "Critical"
            if score >= 7.0: return "High"
            if score >= 4.0: return "Medium"
            if score >  0.0: return "Low"
            return "None"
        except: pass
    return "Unknown"


def process_agent_stats(endpoints):
    versions   = [e.get("agentVersion","Unknown") for e in endpoints if e.get("agentVersion")]
    df_versions = pd.DataFrame(Counter(versions).most_common(20), columns=["Agent Version","Count"])
    attn = Counter()
    for e in endpoints:
        if e.get("missingPermissions"): attn["Missing permission"] += 1; continue
        ua = e.get("userActionsNeeded")
        if ua == "incompatible_os": attn["Incompatible OS"] += 1; continue
        if ua == "unprotected" or e.get("isProtected") is False: attn["Unprotected"] += 1; continue
        op = e.get("operationalState")
        if op in ("shunned","disabled"): attn["Agent suppressed"] += 1; continue
        if ua and ua not in ("none","incompatible_os","unprotected"): attn["Attention needed"] += 1
    df_attn = pd.DataFrame(attn.items(), columns=["Category","Count"])
    return df_versions, df_attn


def process_vulnerabilities(risks):
    app_versions, endpoints_list, severities = [], [], []
    details_rows = []
    for r in risks:
        app_name = r.get("applicationName") or r.get("application") or r.get("appName")
        app_ver  = r.get("applicationVersion") or r.get("application_version") or r.get("version")
        ep       = r.get("endpointName") or r.get("endpoint")
        raw_sev  = r.get("severity")
        nvd      = r.get("nvdBaseScore") or r.get("nvdCvssVersion")
        base     = r.get("baseScore") or r.get("riskScore")
        norm_sev = _normalize_severity(raw_sev, base_score=base, nvd_score=nvd)
        if app_name:
            app_versions.append(f"{app_name} {app_ver}" if app_ver else app_name)
        if ep: endpoints_list.append(ep)
        if norm_sev: severities.append(norm_sev)
        if app_name and ep:
            details_rows.append({
                "Application": app_name, "Version": app_ver or "N/A",
                "Endpoint Name": ep, "Severity": norm_sev or "Unknown"})
    df_details = pd.DataFrame(details_rows)
    if not df_details.empty: df_details = df_details.sort_values(["Application","Endpoint Name"])
    df_apps = pd.DataFrame(Counter(app_versions).most_common(50), columns=["Application + Version","Count"])
    if not df_apps.empty:
        df_apps.loc[len(df_apps)] = ["Total Occurrences", sum(Counter(app_versions).values())]
    df_eps  = pd.DataFrame(Counter(endpoints_list).most_common(50), columns=["Endpoint Name","Count"])
    if not df_eps.empty:
        df_eps.loc[len(df_eps)] = ["Total Occurrences", sum(Counter(endpoints_list).values())]
    df_sev  = pd.DataFrame(Counter(severities).most_common(50), columns=["Severity","Count"])
    if not df_sev.empty:
        df_sev.loc[len(df_sev)] = ["Total Occurrences", sum(Counter(severities).values())]
    return df_details, df_apps, df_eps, df_sev, len(set(endpoints_list))


def build_site_summary(site_name, threats, risks, endpoints, df_hashes, df_hash_summary):
    df_av, df_attn = process_agent_stats(endpoints)
    th_eps   = [t.get("agentRealtimeInfo",{}).get("agentComputerName","N/A") for t in threats]
    th_class = [t.get("threatInfo",{}).get("classification","N/A") for t in threats]
    th_mit   = [t.get("threatInfo",{}).get("mitigationStatusDescription","N/A") for t in threats]
    df_class = pd.DataFrame(Counter(th_class).most_common(30), columns=["Threat Classification","Count"])
    if not df_class.empty: df_class.loc[len(df_class)] = ["Total Occurrences", len(threats)]
    df_ep_cnt = pd.DataFrame(Counter(th_eps).most_common(30), columns=["Endpoint","Count"])
    df_mit    = pd.DataFrame(Counter(th_mit).most_common(30), columns=["Mitigation Status","Count"])
    if not df_mit.empty: df_mit.loc[len(df_mit)] = ["Total Occurrences", len(threats)]

    detailed = []
    for t in threats:
        ti  = t.get("threatInfo", {})
        ari = t.get("agentRealtimeInfo", {})
        ep  = ari.get("agentComputerName","N/A")
        tf  = (ti.get("displayName") or ti.get("threatName") or ti.get("processName") or
               (ti.get("filePath","").replace("\\","/").split("/")[-1]) or "N/A")
        try:
            cat = datetime.fromisoformat(ti.get("createdAt","").replace("Z","+00:00")).strftime("%Y-%m-%d • %H:%M:%S")
        except: cat = ti.get("createdAt","N/A")
        try:
            upd = datetime.fromisoformat(ti.get("updatedAt","").replace("Z","+00:00")).strftime("%Y-%m-%d • %H:%M:%S")
        except: upd = ti.get("updatedAt","N/A")
        detailed.append({
            "ENDPOINT": ep, "REPORTED TIME": cat, "UPDATED TIME": upd,
            "THREAT FILE": tf, "THREAT CLASSIFICATION": ti.get("classification","N/A"),
            "AGENT VERSION": ari.get("agentVersion","N/A"),
            "MITIGATION STATUS": ti.get("mitigationStatusDescription","N/A"),
            "RESOLUTION STATUS": ti.get("incidentStatus","N/A"),
            "ANALYST VERDICT": ti.get("analystVerdict","N/A"),
        })
    df_detailed = pd.DataFrame(detailed)
    if not df_detailed.empty:
        gcols = ["ENDPOINT","REPORTED TIME","UPDATED TIME","THREAT FILE","THREAT CLASSIFICATION",
                 "AGENT VERSION","MITIGATION STATUS","RESOLUTION STATUS","ANALYST VERDICT"]
        df_detailed = df_detailed.groupby(gcols).size().reset_index(name="COUNT")
        df_detailed = df_detailed[["ENDPOINT","COUNT"] + [c for c in gcols if c != "ENDPOINT"]]
        df_detailed = df_detailed.sort_values("COUNT", ascending=False)

    tf_vals = [d.get("THREAT FILE") for d in detailed if d.get("THREAT FILE") != "N/A"]
    df_tf   = pd.DataFrame(Counter(tf_vals).most_common(50), columns=["Threat File","Count"])
    if not df_tf.empty: df_tf.loc[len(df_tf)] = ["Total Occurrences", sum(Counter(tf_vals).values())]

    df_vd, df_va, df_ve, df_vs, uv_eps = process_vulnerabilities(risks)
    df_hs  = pd.DataFrame([{"Total Blocklisted Hashes": len(df_hashes)}])
    ep_names = [e.get("computerName") for e in endpoints if e.get("computerName")]
    os_names = [e.get("osType") for e in endpoints if e.get("osType")]
    df_ep_list = pd.DataFrame(ep_names, columns=["Endpoint Name"])
    df_os  = pd.DataFrame(Counter(os_names).items(), columns=["OS Type","Count"])

    return {
        "site_name": site_name,
        "df_threat_class": df_class, "df_threat_endpoints": df_ep_cnt,
        "df_threat_mit": df_mit, "df_threat_files": df_tf,
        "df_grouped_threats": df_detailed,
        "df_vuln_sev": df_vs, "df_vuln_details": df_vd,
        "df_vuln_apps": df_va, "df_vuln_eps": df_ve,
        "df_hashes": df_hashes, "df_hash_summary": df_hs,
        "df_endpoints_list": df_ep_list, "df_os_table": df_os,
        "df_agent_versions": df_av, "df_agent_attention": df_attn,
        "raw_counts": {
            "total_threats": len(threats), "total_vulnerabilities": len(risks),
            "total_endpoints": len(ep_names), "total_hashes": len(df_hashes),
            "unique_vuln_endpoints": uv_eps,
        },
    }


def export_site_to_excel(summary: dict) -> BytesIO:
    buf = BytesIO()
    with pd.ExcelWriter(buf, engine="xlsxwriter") as w:
        def _write(df, sheet):
            if df is not None and not (hasattr(df, "empty") and df.empty):
                df.to_excel(w, index=False, sheet_name=sheet[:31])
        _write(summary.get("df_grouped_threats"),   "Detailed Threats")
        _write(summary.get("df_threat_class"),       "Threat Classification")
        _write(summary.get("df_threat_mit"),         "Mitigation Status")
        _write(summary.get("df_threat_files"),       "Threat Files")
        _write(summary.get("df_vuln_details"),       "Vulnerability Details")
        _write(summary.get("df_vuln_sev"),           "Vuln Severity")
        _write(summary.get("df_vuln_apps"),          "Vuln Applications")
        _write(summary.get("df_endpoints_list"),     "Endpoints List")
        _write(summary.get("df_os_table"),           "OS Distribution")
        _write(summary.get("df_agent_versions"),     "Agent Versions")
        _write(summary.get("df_agent_attention"),    "Agent Attention")
        _write(summary.get("df_hashes"),             "Blocklisted Hashes")
    buf.seek(0)
    return buf
