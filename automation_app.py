import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timezone
from io import BytesIO
from collections import Counter
import time
import re
import matplotlib.pyplot as plt
import pyotp
import qrcode
import base64
# --------------------
# CONFIG
# --------------------
BASE_URL = "https://euce1-exclusive.sentinelone.net/web/api/v2.1"
API_TOKEN = st.secrets["general"]["api_token"]
HEADERS = {
    "Authorization": f"ApiToken {API_TOKEN}",
    "Content-Type": "application/json"
}
# --------------------
# SITE PIN CONFIGURATION
# --------------------
# Map site names to their required PINs
# TODO: Move to environment variables or encrypted config for production
SITE_PINS = {
    "Default site": "Decipher211$",
    "RoutePay": "Decipher777$",
    "Infoprive Systems": "Decipher222$",
    "Zone Payment Network Limited": "Decipher555$",
    "Qore Inc Technologies": "Decipher666$",
    "SunTrust Bank": "Decipher888$",
    "Cybervergent": "Decipher111$",
    "eTranzact": "Decipher333$"
}
# Session timeout in minutes (set to 0 to require re-authentication after each fetch)
SESSION_TIMEOUT_MINUTES = 0  # Change this to set timeout duration
# --------------------
# TOTP (Google Authenticator) CONFIGURATION
# --------------------
# Generate a new secret with: pyotp.random_base32()
# IMPORTANT: Keep this secret secure and do not share it
# This is a PERMANENT secret - do not change it or users will need to re-scan QR code
# Base32 only allows: A-Z and 2-7 (no 0, 1, 8, 9)
TOTP_SECRET = st.secrets["general"]["totp_secret"]
TOTP_APP_NAME = "SentinelOne Dashboard"
TOTP_ISSUER = "Esentry Security"  # Your organization name
# --------------------
# Helper: Cursor Pagination
# --------------------
def fetch_all_with_cursor(endpoint, params=None, timeout=30):
    if params is None:
        params = {}
    all_items = []
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    cursor = None
    params = params.copy()
    while True:
        if cursor:
            params["cursor"] = cursor
        try:
            resp = requests.get(url, headers=HEADERS, params=params, timeout=timeout)
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
# Fetch functions
# --------------------
def fetch_sites():
    try:
        sites = fetch_all_with_cursor("sites", {"limit": 200})
        if not isinstance(sites, list):
            sites = []
        return sites
    except Exception as e:
        st.error(f"Error fetching sites: {e}")
        return []
def fetch_endpoints_for_site(site_id):
    try:
        return fetch_all_with_cursor("agents", {"siteIds": site_id, "limit": 1000})
    except:
        return []
def fetch_threats_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("threats", {
            "siteIds": site_id,
            "createdAt__gte": start_iso,
            "createdAt__lte": end_iso,
            "limit": 1000,
            "sortBy": "createdAt",
            "sortOrder": "desc"
        })
    except:
        return []
def fetch_risks_for_site(site_id, start_iso, end_iso):
    try:
        return fetch_all_with_cursor("application-management/risks", {
            "siteIds": site_id,
            "detectionDate__gte": start_iso,
            "detectionDate__lte": end_iso,
            "limit": 1000,
            "sortBy": "detectionDate",
            "sortOrder": "desc"
        })
    except:
        return []
        
def render_pie_chart(df, label_col, value_col, title):
    if label_col not in df.columns or value_col not in df.columns:
        return  # silently skip invalid dataframes
    df = df[df[label_col] != "Total Occurrences"]
    if df.empty:
        return
    
    # Set modern, beautiful font - Segoe UI
    plt.rcParams['font.family'] = 'Segoe UI'
    
    # Set dark theme for pie chart - compact size for most charts
    fig, ax = plt.subplots(figsize=(3, 3), facecolor='#0E1117')
    ax.set_facecolor('#0E1117')
    
    # Limit to top 10 items to prevent overcrowding
    df_display = df.head(10).copy()
    
    # Vibrant, appealing color palette
    colors = [
        '#1E3A8A',  # Dark Blue (Malware)
        '#FF6B00',  # Bright Orange (Ransomware)
        '#10B981',  # Vibrant Green (Cryptominer/Packed)
        '#DC2626',  # Crimson Red (Infostealer)
        '#8B5CF6',  # Purple (General)
        '#92400E',  # Brown (General/Total)
        '#EC4899',  # Hot Pink (AvLaunch)
        '#6B7280',  # Grey (uesAgentService)
        '#F59E0B',  # Gold/Amber (RtkAudUService64)
        '#06B6D4',  # Cyan (Antigravity)
    ]
    
    # Create pie chart with compact layout
    wedges, texts, autotexts = ax.pie(
        df_display[value_col],
        labels=None,  # Use legend instead
        autopct=lambda pct: f'{pct:.1f}%' if pct > 2 else '',
        startangle=90,
        colors=colors[:len(df_display)],
        pctdistance=0.7,
        textprops={"fontsize": 7, "color": "white", "weight": "bold"},
        radius=0.9
    )
    
    for t in autotexts:
        t.set_fontsize(7)
        t.set_color('white')
        t.set_weight('bold')
    
    # Add legend on the right side
    legend = ax.legend(
        wedges, 
        df_display[label_col],
        title="",
        loc="center left",
        bbox_to_anchor=(1, 0.5),
        fontsize=7,
        facecolor='#0E1117',
        edgecolor='#0E1117',
        labelcolor='white',
        prop={'family': 'Segoe UI', 'size': 7},
        frameon=False
    )
    
    ax.axis("equal")
    ax.set_title(title, fontsize=10, color='white', pad=12, weight='bold')
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
def render_pie_chart_wide(df, label_col, value_col, title):
    """Wide landscape pie chart specifically for Threat File Distribution to prevent overlap."""
    if label_col not in df.columns or value_col not in df.columns:
        return
    df = df[df[label_col] != "Total Occurrences"]
    if df.empty:
        return
    
    plt.rcParams['font.family'] = 'Segoe UI'
    
    # Wide landscape layout
    fig, ax = plt.subplots(figsize=(10, 5), facecolor='#0E1117')
    ax.set_facecolor('#0E1117')
    
    df_display = df.head(10).copy()
    
    colors = [
        '#1E3A8A', '#FF6B00', '#10B981', '#DC2626', '#8B5CF6',
        '#92400E', '#EC4899', '#6B7280', '#F59E0B', '#06B6D4',
    ]
    
    # Pie positioned on left with space for legend on right
    wedges, texts, autotexts = ax.pie(
        df_display[value_col],
        labels=None,
        autopct=lambda pct: f'{pct:.1f}%' if pct > 2 else '',
        startangle=90,
        colors=colors[:len(df_display)],
        pctdistance=0.75,
        textprops={"fontsize": 10, "color": "white", "weight": "bold"},
        radius=1.0,
        center=(-0.45, 0)  # Shift pie further left
    )
    
    for t in autotexts:
        t.set_fontsize(10)
        t.set_color('white')
        t.set_weight('bold')
    
    legend = ax.legend(
        wedges, 
        df_display[label_col],
        title="",
        loc="center left",
        bbox_to_anchor=(0.85, 0.5),  # Move legend further right
        fontsize=9,
        facecolor='#0E1117',
        edgecolor='#0E1117',
        labelcolor='white',
        prop={'family': 'Segoe UI', 'size': 9},
        frameon=False
    )
    
    ax.axis("equal")
    ax.set_title(title, fontsize=14, color='white', pad=20, weight='bold')
    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
def render_bar_chart(df, label_col, value_col, title, color="#5A4FCF"):
    if df.empty:
        st.info(f"No data for {title}")
        return
    
    fig, ax = plt.subplots(figsize=(5, 3))
    ax.bar(df[label_col], df[value_col], color=color)
    ax.set_title(title, fontsize=10)
    ax.set_ylabel("Count")
    plt.xticks(rotation=45, ha='right')
    st.pyplot(fig)
# --------------------
# Styling Helper Functions
# --------------------
def style_dataframe_with_gradient(df, value_col="Count"):
    """
    Applies a gradient color to the Count column only.
    Uses light blue to dark blue gradient.
    """
    if df.empty or value_col not in df.columns:
        return df
    
    # Exclude 'Total Occurrences' row from gradient
    styled = df.style.background_gradient(
        cmap='Blues',
        subset=[value_col],
        vmin=df[df.iloc[:, 0] != "Total Occurrences"][value_col].min() if len(df) > 1 else 0,
        vmax=df[df.iloc[:, 0] != "Total Occurrences"][value_col].max() if len(df) > 1 else 1
    )
    return styled
def style_severity_dataframe(df):
    """
    Applies severity-based colors ONLY to the Count column.
    Color palette: Light Blue, Dark Blue, Red, Orange, Dark Green, Brown
    """
    if df.empty or "Severity" not in df.columns or "Count" not in df.columns:
        return df
    
    def highlight_count_by_severity(s):
        colors = []
        for idx, val in enumerate(df["Severity"]):
            severity = str(val).lower()
            if "critical" in severity:
                colors.append('background-color: #DC143C; color: white')  # Red
            elif "high" in severity:
                colors.append('background-color: #FF8C00; color: white')  # Orange (DarkOrange)
            elif "medium" in severity:
                colors.append('background-color: #00008B; color: white')  # Dark Blue
            elif "low" in severity:
                colors.append('background-color: #006400; color: white')  # Dark Green
            elif "informational" in severity or "info" in severity:
                colors.append('background-color: #87CEEB; color: black')  # Light Blue
            elif "total" in severity:
                colors.append('background-color: #8B4513; color: white; font-weight: bold')  # Brown
            else:
                colors.append('background-color: #87CEEB; color: black')  # Light Blue (default)
        return colors
    
    return df.style.apply(highlight_count_by_severity, subset=["Count"])
def style_mitigation_dataframe(df):
    """
    Applies color coding ONLY to the Count column based on mitigation status.
    Color palette: Light Blue, Dark Blue, Red, Orange, Dark Green, Brown
    """
    if df.empty or "Count" not in df.columns:
        return df
    
    # Get the name of the first column (could be "Mitigation Status" or "Threat Classification")
    label_col = df.columns[0]
    
    def highlight_count_by_status(s):
        colors = []
        for idx, val in enumerate(df[label_col]):
            status = str(val).lower()
            if "mitigated" in status and "not" not in status:
                colors.append('background-color: #006400; color: white')  # Dark Green
            elif "not mitigated" in status:
                colors.append('background-color: #DC143C; color: white')  # Red
            elif "benign" in status or "marked as benign" in status:
                colors.append('background-color: #87CEEB; color: black')  # Light Blue
            elif "total" in status:
                colors.append('background-color: #8B4513; color: white; font-weight: bold')  # Brown
            else:
                colors.append('background-color: #FF8C00; color: black')  # Orange
        return colors
    
    return df.style.apply(highlight_count_by_status, subset=["Count"])
def style_threat_classification_dataframe(df):
    """
    Applies color coding ONLY to the Count column based on threat classification.
    Specific colors: Dark Blue for Malware, Light Blue for Ransomware, Brown for Cryptominer, etc.
    """
    if df.empty or "Count" not in df.columns:
        return df
    
    # Get the name of the first column (should be "Threat Classification")
    label_col = df.columns[0]
    
    def highlight_count_by_threat_type(s):
        colors = []
        for idx, val in enumerate(df[label_col]):
            threat_type = str(val).lower()
            if "malware" in threat_type:
                colors.append('background-color: #00008B; color: white')  # Dark Blue
            elif "ransomware" in threat_type:
                colors.append('background-color: #87CEEB; color: black')  # Light Blue
            elif "cryptominer" in threat_type:
                colors.append('background-color: #8B4513; color: white')  # Brown
            elif "packed" in threat_type:
                colors.append('background-color: #FF8C00; color: white')  # Orange
            elif "infostealer" in threat_type:
                colors.append('background-color: #006400; color: white')  # Dark Green
            elif "general" in threat_type:
                colors.append('background-color: #DC143C; color: white')  # Red
            elif "total" in threat_type:
                colors.append('background-color: #8B4513; color: white; font-weight: bold')  # Brown (bold)
            else:
                colors.append('background-color: #696969; color: white')  # Grey (default)
        return colors
    
    return df.style.apply(highlight_count_by_threat_type, subset=["Count"])
def process_agent_stats(endpoints):
    # --- Agent Version Coverage ---
    versions = [e.get("agentVersion", "Unknown") for e in endpoints]
    # Filter out None/Empty
    versions = [v for v in versions if v]
    
    # Get top 20 versions
    df_versions = pd.DataFrame(Counter(versions).most_common(20), columns=["Agent Version", "Count"])
    # --- Agents Requiring Attention ---
    # Categories: Missing permission, Attention needed, Agent suppressed, Unprotected, Incompatible OS
    attention_counts = Counter()
    
    for e in endpoints:
        # 1. Missing Permission
        # Check for non-empty missingPermissions list or specific flag
        missing_perms = e.get("missingPermissions")
        if missing_perms:
            attention_counts["Missing permission"] += 1
            # We assume a single primary status per agent for the chart, but an agent could have multiple issues.
            # Prioritizing in order of severity/commonality.
            continue 
        # 2. Incompatible OS
        ua = e.get("userActionsNeeded")
        if ua == "incompatible_os":
             attention_counts["Incompatible OS"] += 1
             continue
        # 3. Unprotected
        # 'protectionEnabled' is false or ua is unprotected
        if ua == "unprotected" or e.get("isProtected") is False:
             attention_counts["Unprotected"] += 1
             continue
             
        # 4. Agent Suppressed
        # operationalState is 'shunned' often maps to suppressed
        op_state = e.get("operationalState")
        if op_state == "shunned" or op_state == "disabled":
             attention_counts["Agent suppressed"] += 1
             continue
             
        # 5. Attention needed (Generic/Other)
        # reboot_needed, upgrade_needed, user_action_needed
        if ua and ua not in ["none", "incompatible_os", "unprotected"]:
            attention_counts["Attention needed"] += 1
            continue
    
    df_attention = pd.DataFrame(attention_counts.items(), columns=["Category", "Count"])
    
    return df_versions, df_attention
# --------------------
# Robust Blocklisted Hashes
# --------------------
def fetch_blocklisted_hashes_for_site(site_id, start_iso=None, end_iso=None): 
    """
    Fetch blocklisted hashes (restrictions) for a specific site within a date range.
    Uses the /restrictions endpoint with type=black_hash for hash items.
    Returns site-specific restrictions PLUS inherited group/account level restrictions.
    """
    try:
        # Fetch hash restrictions for this specific site
        # siteIds = filter to this site
        # includeParents = also get group/account level restrictions that apply to this site
        params = {
            "limit": 1000,
            "type": "black_hash",      # Filter for hash blocklist items only
            "siteIds": site_id,        # Filter to this specific site
            "includeParents": "true"   # Include inherited group/account level restrictions
        }
        
        # Fetch restrictions for this site (including inherited ones)
        all_data = fetch_all_with_cursor("restrictions", params)
        
        # Parse date range for client-side filtering
        start_dt = None
        end_dt = None
        if start_iso:
            try:
                start_dt = datetime.fromisoformat(start_iso.replace("Z", "+00:00"))
            except:
                pass
        if end_iso:
            try:
                end_dt = datetime.fromisoformat(end_iso.replace("Z", "+00:00"))
            except:
                pass
        rows = []
        
        for item in all_data:
            if not isinstance(item, dict):
                continue
            # Get hash value (could be sha256Value or value field)
            sha256 = item.get("sha256Value") or item.get("value")
            if not sha256:
                continue
            
            # Get updated date for client-side filtering
            updated_at_str = item.get("updatedAt", "")
            
            # Client-side date filtering on updatedAt
            if start_dt or end_dt:
                if updated_at_str:
                    try:
                        updated_dt = datetime.fromisoformat(updated_at_str.replace("Z", "+00:00"))
                        if start_dt and updated_dt < start_dt:
                            continue
                        if end_dt and updated_dt > end_dt:
                            continue
                    except:
                        pass  # If date parsing fails, include the item
            
            # Get other fields
            os_type = item.get("osType", "Unknown")
            description = item.get("description", "")
            source = item.get("source", "Unknown")
            created_at = item.get("createdAt", "")
            scope_name = item.get("scopeName", "")
            user_name = item.get("userName", "")
            imported = item.get("imported", False)
            not_recommended = item.get("notRecommended", "")
            
            rows.append({
                "Hash Value": sha256,
                "OS Type": os_type,
                "Description": description,
                "Source": source,
                "Last Updated": updated_at_str,
                "Created At": created_at,
                "Scope": scope_name,
                "User": user_name,
                "Imported": "Yes" if imported else "No",
                "Not Recommended": not_recommended if not_recommended else "N/A"
            })
        df_hashes = pd.DataFrame(rows)
        
        if df_hashes.empty:
            df_hashes = pd.DataFrame(columns=[
                "Hash Value", "OS Type", "Description", "Source", 
                "Last Updated", "Created At", "Scope", "User", "Imported", "Not Recommended"
            ])
            return (
                df_hashes,
                pd.DataFrame(columns=["OS Type", "Count"])
            )
        # OS distribution summary
        df_hash_summary = (
            df_hashes
            .groupby("OS Type")
            .size()
            .reset_index(name="Count")
        )
        
        # Total row
        df_hash_summary.loc[len(df_hash_summary.index)] = [
            "Total",
            len(df_hashes)
        ]
        return df_hashes, df_hash_summary
    except Exception as e:
        st.error(f"Error fetching blocklisted hashes: {e}")
        return (
            pd.DataFrame(columns=[
                "Hash Value", "OS Type", "Description", "Source",
                "Last Updated", "Created At", "Scope", "User", "Imported", "Not Recommended"
            ]),
            pd.DataFrame(columns=["OS Type", "Count"])
        )
# --------------------
# Vulnerability helpers
# --------------------
def _normalize_severity(raw_sev, base_score=None, nvd_score=None):
    if raw_sev and isinstance(raw_sev, str):
        s = raw_sev.strip()
        m = re.match(r"(?i)^(critical|crit|high|medium|med|low|info|informational|none|false positive|false_positive|false|unknown)\b", s)
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
        if ep: endpoints.append(ep)
        raw_sev = r.get("severity")
        nvd_score = r.get("nvdBaseScore") or r.get("nvdCvssVersion")
        base_score = r.get("baseScore") or r.get("riskScore")
        normalized = _normalize_severity(raw_sev, base_score=base_score, nvd_score=nvd_score)
        if normalized: severities.append(normalized)
    df_app_versions = pd.DataFrame(Counter(app_versions).most_common(50), columns=["Application + Version", "Count"])
    df_app_versions.loc[len(df_app_versions.index)] = ["Total Occurrences", sum(Counter(app_versions).values())]
    df_endpoints = pd.DataFrame(Counter(endpoints).most_common(50), columns=["Endpoint Name", "Count"])
    df_endpoints.loc[len(df_endpoints.index)] = ["Total Occurrences", sum(Counter(endpoints).values())]
    df_severity = pd.DataFrame(Counter(severities).most_common(50), columns=["Severity", "Count"])
    df_severity.loc[len(df_severity.index)] = ["Total Occurrences", sum(Counter(severities).values())]
    unique_vuln_endpoints = len(set(endpoints))
    # New detailed list calculation
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
# --------------------
# Summary builder
# --------------------
def build_site_summary(site_name, threats, risks, endpoints, df_hashes, df_hash_summary):
    # Process agent stats (Versions, Attention)
    df_agent_versions, df_agent_attention = process_agent_stats(endpoints)
    threat_endpoints = [t.get("agentRealtimeInfo", {}).get("agentComputerName", "N/A") for t in threats]
    threat_classifications = [t.get("threatInfo", {}).get("classification", "N/A") for t in threats]
    threat_mitigations = [t.get("threatInfo", {}).get("mitigationStatusDescription", "N/A") for t in threats]
    df_threat_class = pd.DataFrame(Counter(threat_classifications).most_common(30), columns=["Threat Classification", "Count"])
    df_threat_class.loc[len(df_threat_class.index)] = ["Total Occurrences", sum(Counter(threat_classifications).values())]
    df_threat_endpoints = pd.DataFrame(Counter(threat_endpoints).most_common(30), columns=["Endpoint", "Count"])
    df_threat_mit = pd.DataFrame(Counter(threat_mitigations).most_common(30), columns=["Mitigation Status", "Count"])
    df_threat_mit.loc[len(df_threat_mit.index)] = ["Total Occurrences", sum(Counter(threat_mitigations).values())]
    # --- New Detailed Threat List Calculation ---
    detailed_threats = []
    for t in threats:
        # threatInfo object
        ti = t.get("threatInfo", {})
        # agentRealtimeInfo object
        ari = t.get("agentRealtimeInfo", {})
        
        endpoint = ari.get("agentComputerName", "N/A")
        
        # Threat File: robust fallback strategy
        threat_file = ti.get("displayName")
        if not threat_file:
             threat_file = ti.get("threatName")
        if not threat_file:
             threat_file = ti.get("processName")
        if not threat_file:
             raw_path = ti.get("filePath")
             if raw_path:
                 threat_file = raw_path.replace("\\", "/").split("/")[-1]
        
        if not threat_file:
             threat_file = "N/A"
        
        classification = ti.get("classification", "N/A")
        mitigation = ti.get("mitigationStatusDescription") or ti.get("mitigationStatus", "N/A")
        resolution = ti.get("incidentStatus", "N/A")
        verdict = ti.get("analystVerdict", "N/A")
        
        # New Fields: Reported Time, Updated Time, Agent Version
        created_at_raw = ti.get("createdAt")
        updated_at_raw = ti.get("updatedAt")
        agent_version = ari.get("agentVersion", "N/A")
        # Format Dates
        reported_time = "N/A"
        updated_time = "N/A"
        
        try:
            if created_at_raw:
                dt_c = datetime.fromisoformat(created_at_raw.replace('Z', '+00:00'))
                reported_time = dt_c.strftime('%Y-%m-%d • %H:%M:%S')
            
            if updated_at_raw:
                dt_u = datetime.fromisoformat(updated_at_raw.replace('Z', '+00:00'))
                # Manual suffix logic for "Jan 30th"
                day = dt_u.day
                sfx = 'th' if 11<=day<=13 else {1:'st',2:'nd',3:'rd'}.get(day%10, 'th')
                updated_time = dt_u.strftime(f'%b {day}{sfx} %Y • %H:%M:%S')
        except Exception:
            pass
        detailed_threats.append({
            "ENDPOINT": endpoint,
            "REPORTED TIME": reported_time,
            "UPDATED TIME": updated_time,
            "THREAT FILE": threat_file,
            "THREAT CLASSIFICATION": classification,
            "AGENT VERSION": agent_version,
            "THREAT MITIGATION STATUS": mitigation,
            "THREAT RESOLUTION STATUS": resolution,
            "ANALYST VERDICT": verdict
        })
    df_detailed_threats = pd.DataFrame(detailed_threats)
    
    # Group by all columns (except count) and count occurrences
    if not df_detailed_threats.empty:
         # Define columns to group by (all display columns)
         group_cols = ["ENDPOINT", "REPORTED TIME", "UPDATED TIME", "THREAT FILE", "THREAT CLASSIFICATION", "AGENT VERSION", "THREAT MITIGATION STATUS", "THREAT RESOLUTION STATUS", "ANALYST VERDICT"]
         
         df_grouped_threats = df_detailed_threats.groupby(group_cols).size().reset_index(name="COUNT")
         
         # Reorder columns: Endpoint, Count, then the rest
         display_cols = ["ENDPOINT", "COUNT"] + [c for c in group_cols if c != "ENDPOINT"]
         df_grouped_threats = df_grouped_threats[display_cols]
         
         # Sort by Count desc
         df_grouped_threats = df_grouped_threats.sort_values(by="COUNT", ascending=False)
    else:
         df_grouped_threats = pd.DataFrame(columns=["ENDPOINT", "COUNT", "REPORTED TIME", "UPDATED TIME", "THREAT FILE", "THREAT CLASSIFICATION", "AGENT VERSION", "THREAT MITIGATION STATUS", "THREAT RESOLUTION STATUS", "ANALYST VERDICT"])
    # --------------------------------------------
    
    # --- Threat File Counts (just the files, not grouped by endpoint) ---
    threat_files = [t.get("THREAT FILE") for t in detailed_threats if t.get("THREAT FILE") != "N/A"]
    df_threat_files = pd.DataFrame(Counter(threat_files).most_common(50), columns=["Threat File", "Count"])
    if not df_threat_files.empty:
        df_threat_files.loc[len(df_threat_files.index)] = ["Total Occurrences", sum(Counter(threat_files).values())]
    df_vuln_details, df_vuln_apps, df_vuln_eps, df_vuln_sev, unique_vuln_endpoints = process_vulnerabilities(risks)
    df_hash_summary = pd.DataFrame(
        [{"Total Blocklisted Hashes": len(df_hashes)}]
)
 
    ep_names = [e.get("computerName") for e in endpoints if e.get("computerName")]
    os_names = [e.get("osType") for e in endpoints if e.get("osType")]
    unique_os = sorted(set(os_names))
    df_sentinel_summary = pd.DataFrame([{
        "Total endpoints discovered": len(ep_names),
        "Total OS entries": len(unique_os),
        "OS Types": ", ".join(unique_os)
    }])
    df_endpoints_list = pd.DataFrame(ep_names, columns=["Endpoint Name"])
    os_table = Counter([(o if o is not None else "Unknown") for o in os_names])
    df_os_table = pd.DataFrame(os_table.items(), columns=["OS Type", "Count"])
    return {
        "site_name": site_name,
        "df_threat_class": df_threat_class,
        "df_threat_endpoints": df_threat_endpoints,
        "df_threat_mit": df_threat_mit,
        "df_threat_files": df_threat_files,  # <--- Threat file counts
        "df_grouped_threats": df_grouped_threats,  # <--- Added
        "df_vuln_sev": df_vuln_sev,
        "df_vuln_details": df_vuln_details,
        "df_vuln_apps": df_vuln_apps,
        "df_vuln_eps": df_vuln_eps,
        "df_hashes": df_hashes,
        "df_hash_summary": df_hash_summary,
        "df_sentinel_summary": df_sentinel_summary,
        "df_endpoints_list": df_endpoints_list,
        "df_os_table": df_os_table,
        "df_agent_versions": df_agent_versions,
        "df_agent_attention": df_agent_attention,
        "raw_counts": {
            "total_threats": len(threats),
            "total_vulnerabilities": len(risks),
            "total_endpoints": len(ep_names),
            "total_hashes": len(df_hashes),
            "unique_vuln_endpoints": unique_vuln_endpoints
        }
    }
# --------------------
# Streamlit UI
# --------------------
st.set_page_config(page_title="SentinelOne Dashboard", layout="wide")
# Header with Logo
col_logo, col_title = st.columns([1, 15])
with col_logo:
    # SentinelOne Purple Logo
    st.image("s1_logo.png", width=100)
with col_title:
    st.title("SentinelOne - Reporting Visualization")
st.markdown(
    "Enter a date range and click **Fetch**. The app will query Threats, Vulnerabilities, Agents & Restrictions "
    "from SentinelOne, summarize them, and let you download a full Excel report."
)
# ========================================
# TOTP AUTHENTICATION GATE (Layer 1 Security)
# ========================================
# Initialize TOTP authentication state
if "totp_authenticated" not in st.session_state:
    st.session_state.totp_authenticated = False
# Check if user has authenticated with TOTP
if not st.session_state.totp_authenticated:
    # Auth Header with Logo (Using HTML Flexbox for perfect alignment)
    with open("s1_logo.png", "rb") as f:
        data = f.read()
        encoded = base64.b64encode(data).decode()
    
    st.markdown(f"""
    <div style="display: flex; align-items: center;">
        <img src="data:image/png;base64,{encoded}" width="50" style="margin-right: 15px;">
        <h1 style="margin: 0; padding: 0;">🔐 SentinelOne Dashboard - Authentication Required</h1>
    </div>
    """, unsafe_allow_html=True)
    
    
    # Create TOTP object
    totp = pyotp.TOTP(TOTP_SECRET)
    
    # Generate provisioning URI for QR code
    provisioning_uri = totp.provisioning_uri(
        name=TOTP_APP_NAME,
        issuer_name=TOTP_ISSUER
    )
    
    # Display setup instructions
    # with st.expander("🆕 First Time Setup - Click Here", expanded=True):
    #     st.markdown("""
    #     **Instructions:**
    #     1. Install **Google Authenticator** app on your phone:
    #        - [iOS App Store](https://apps.apple.com/app/google-authenticator/id388497605)
    #        - [Android Play Store](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
    #     2. Open the app and tap **"+"** or **"Add account"**
    #     3. Select **"Scan a QR code"**
    #     4. Scan the QR code below
    #     5. Enter the 6-digit code from the app
    #     """)
        
    #     # Generate QR code
    #     qr = qrcode.QRCode(version=1, box_size=10, border=4)
    #     qr.add_data(provisioning_uri)
    #     qr.make(fit=True)
    #     qr_img = qr.make_image(fill_color="black", back_color="white")
    #     
    #     # Display QR code
    #     st.image(qr_img.get_image(), caption="Scan this QR code with Google Authenticator", width=300)
    
    # Show manual entry option
    # with st.expander("⌨️ Manual Entry (Alternative)"):
    #     st.code(TOTP_SECRET)
    #     st.caption(f"Account name: {TOTP_APP_NAME}")
    #     st.caption(f"Issuer: {TOTP_ISSUER}")
    
    # Authentication form
    st.markdown("---")
    st.markdown("### Enter Verification Code")
    
    col1, col2 = st.columns([2, 1])
    with col1:
        totp_code = st.text_input(
            "6-Digit Code from your Authenticator app",
            max_chars=6,
            placeholder="000000",
            key="totp_input",
            type="password"
        )
    with col2:
        verify_button = st.button("Verify & Access Dashboard", type="primary")
    
    if verify_button:
        if totp_code and len(totp_code) == 6:
            # Verify the TOTP code
            if totp.verify(totp_code, valid_window=1):  # Allow 1 time step before/after for clock drift
                st.session_state.totp_authenticated = True
                st.success("✅ Authentication successful! Redirecting to dashboard...")
                st.rerun()
            else:
                st.error("❌ Invalid code. Please check the code in your Google Authenticator app and try again.")
        else:
            st.warning("⚠️ Please enter a 6-digit code.")
    
    st.stop()  # Stop execution here if not authenticated
# ========================================
# MAIN DASHBOARD (Only accessible after TOTP authentication)
# ========================================
col1, col2 = st.columns(2)
with col1:
    start_date = st.date_input("📅 Start Date", value=datetime.now(timezone.utc).date().replace(day=1))
    start_time_str = st.text_input("🕒 Start Time (HH:MM)", value="00:00", placeholder="00:00")
with col2:
    end_date = st.date_input("📅 End Date", value=datetime.now(timezone.utc).date())
    end_time_str = st.text_input("🕒 End Time (HH:MM)", value="23:59", placeholder="23:59")
# Parse time strings
try:
    start_time = datetime.strptime(start_time_str, "%H:%M").time()
except ValueError:
    st.error("Invalid start time format. Please use HH:MM (e.g., 09:30)")
    st.stop()
try:
    end_time = datetime.strptime(end_time_str, "%H:%M").time()
except ValueError:
    st.error("Invalid end time format. Please use HH:MM (e.g., 23:59)")
    st.stop()
# Validate start < end (combining date + time)
start_dt = datetime.combine(start_date, start_time)
end_dt = datetime.combine(end_date, end_time)
if start_dt > end_dt:
    st.error("Start date/time must be before or equal to End date/time.")
    st.stop()
sites = fetch_sites()
site_options = {s.get("name"): s.get("id") for s in sites}
selected = st.multiselect("Select site(s)", options=list(site_options.keys()), default=list(site_options.keys())[:2])
if not selected:
    st.info("Please select at least one site.")
    st.stop()
# Initialize session state for authenticated sites with timestamps
if "authenticated_sites" not in st.session_state:
    st.session_state.authenticated_sites = {}
if "auth_timestamps" not in st.session_state:
    st.session_state.auth_timestamps = {}
if "data_fetched" not in st.session_state:
    st.session_state.data_fetched = False
# Check for timeout and clear expired authentications
from datetime import datetime, timedelta
current_time = datetime.now()
expired_sites = []
for site_name, auth_time in st.session_state.auth_timestamps.items():
    if SESSION_TIMEOUT_MINUTES > 0:
        time_diff = (current_time - auth_time).total_seconds() / 60
        if time_diff > SESSION_TIMEOUT_MINUTES:
            expired_sites.append(site_name)
# Clear expired authentications
for site_name in expired_sites:
    if site_name in st.session_state.authenticated_sites:
        del st.session_state.authenticated_sites[site_name]
    if site_name in st.session_state.auth_timestamps:
        del st.session_state.auth_timestamps[site_name]
if expired_sites:
    st.warning(f"⏰ Authentication expired for: {', '.join(expired_sites)}. Please re-authenticate.")
# PIN Authentication Section
st.subheader("🔐 Site Authentication")
st.write("Enter PIN for each selected site to access data:")
all_authenticated = True
for site_name in selected:
    # Check if site requires a PIN
    if site_name in SITE_PINS:
        # Check if already authenticated in this session
        if site_name in st.session_state.authenticated_sites:
            st.success(f"✅ {site_name}: Authenticated")
        else:
            # Show PIN input
            col1, col2 = st.columns([3, 1])
            with col1:
                entered_pin = st.text_input(
                    f"PIN for {site_name}",
                    type="password",
                    key=f"pin_{site_name}",
                    placeholder="Enter PIN"
                )
            with col2:
                if st.button("Verify", key=f"verify_{site_name}"):
                    if entered_pin == SITE_PINS[site_name]:
                        st.session_state.authenticated_sites[site_name] = True
                        st.session_state.auth_timestamps[site_name] = datetime.now()
                        st.success(f"✅ Access granted to {site_name}")
                        st.rerun()
                    else:
                        st.error(f"❌ Invalid PIN for {site_name}")
            
            if site_name not in st.session_state.authenticated_sites:
                all_authenticated = False
    else:
        # Site doesn't require PIN
        st.info(f"ℹ️ {site_name}: No PIN required")
        st.session_state.authenticated_sites[site_name] = True
        st.session_state.auth_timestamps[site_name] = datetime.now()
# Clear authentication for deselected sites
for auth_site in list(st.session_state.authenticated_sites.keys()):
    if auth_site not in selected:
        del st.session_state.authenticated_sites[auth_site]
        if auth_site in st.session_state.auth_timestamps:
            del st.session_state.auth_timestamps[auth_site]
# Only show fetch button if all sites are authenticated
if not all_authenticated:
    st.warning("⚠️ You need to authenticate sites before fetching data.")
    st.stop()
if st.button("🚀 Fetch Site Data"):
    # Convert to UTC ISO format
    # We treat the input time as local/naive but user wants UTC ideally or we assume system local?
    # SentinelOne expects UTC ("Z"). 
    # If we assume the user enters local time, we might need conversion.
    # For simplicity/consistency with previous logic, we'll treat it as if the user *means* this time in UTC 
    # OR we just attach UTC tzinfo. The previous logic was naive `replace(tzinfo=timezone.utc)`.
    # Let's stick to that: The user input is treated as UTC.
    
    start_iso = start_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    end_iso = end_dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    for site_name in selected:
        site_id = site_options[site_name]
        # Create columns for Header (Left) and Download Button (Right)
        col_header, col_download = st.columns([3, 1])
        with col_header:
            st.header(f"🔹 {site_name}")
        with st.spinner(f"Fetching {site_name}..."):
            endpoints = fetch_endpoints_for_site(site_id)
            threats = fetch_threats_for_site(site_id, start_iso, end_iso)
            risks = fetch_risks_for_site(site_id, start_iso, end_iso)
            df_hashes, df_hash_summary = fetch_blocklisted_hashes_for_site(site_id, start_iso, end_iso)
        summary = build_site_summary(
          site_name,
          threats,
          risks,
          endpoints,
          df_hashes,
          df_hash_summary
)
        st.subheader("🧨Threats Summary")
        st.write("**Threat Classifications by Frequency**")
        st.dataframe(style_threat_classification_dataframe(summary["df_threat_class"]))
        render_pie_chart(
            summary["df_threat_class"],
            "Threat Classification",
            "Count",
            "Threat Classification Distribution"
)
        st.write("**Endpoint Occurrences (Top affected endpoints)**")
        st.dataframe(summary["df_threat_endpoints"])
        render_pie_chart(
            summary["df_threat_endpoints"],
            label_col="Endpoint",
            value_col="Count",
            title="Endpoint Occurrences"
)
        st.write("**Mitigation Status by Frequency**")
        st.dataframe(style_mitigation_dataframe(summary["df_threat_mit"]))
        render_pie_chart(
            summary["df_threat_mit"],
            label_col="Mitigation Status",
            value_col="Count",
            title="Mitigation Status"
)
        # Threat File Counts
        st.write("**Threat File Occurrences**")
        st.dataframe(summary["df_threat_files"])
        render_pie_chart_wide(
            summary["df_threat_files"],
            label_col="Threat File",
            value_col="Count",
            title="Threat File Distribution"
        )
        # Added Detailed Threat List
        with st.expander("See Detailed Threat List", expanded=True):
             st.dataframe(summary["df_grouped_threats"])
   
        st.subheader("🩻 Vulnerabilities Summary")
        st.write(f"Total vulnerabilities: {summary['raw_counts']['total_vulnerabilities']}")
        st.write(f"Total endpoint entries from vulnerabilities: {summary['raw_counts']['unique_vuln_endpoints']}")
        st.write("**Application + Version counts**")
        st.dataframe(summary["df_vuln_apps"])
        st.write("**Top vulnerable endpoints (by occurrences)**")
        st.dataframe(summary["df_vuln_eps"])
        st.write("**Severity (normalized)**")
        st.dataframe(style_severity_dataframe(summary["df_vuln_sev"]))
        with st.expander("See Detailed Vulnerability List (Endpoints per App)"):
            st.dataframe(summary["df_vuln_details"])
        st.subheader("🧩 Blocklisted Hashes")
        st.write(f"Total blocklisted hashes: {summary['raw_counts']['total_hashes']}")
        st.dataframe(summary["df_hashes"])
        st.subheader("🤖 Agent Health & Coverage")
        col_cov1, col_cov2 = st.columns(2)
        
        with col_cov1:
            st.write("**Agents Requiring Attention**")
            render_bar_chart(
                summary["df_agent_attention"], 
                "Category", 
                "Count", 
                "Agents Requiring Attention",
                color="#4B0082" # Indigo-like
            )
            st.dataframe(summary["df_agent_attention"])
        with col_cov2:
            st.write("**Agent Version Coverage**")
            render_bar_chart(
                summary["df_agent_versions"], 
                "Agent Version", 
                "Count", 
                "Agent Version Coverage",
                color="#6A5ACD" # SlateBlue
            )
            st.dataframe(summary["df_agent_versions"])
        st.subheader("🧭 Sentinels Summary")
        st.write(f"Total endpoints discovered: {summary['raw_counts']['total_endpoints']}")
        st.subheader("OS Types Distribution")
        st.dataframe(style_dataframe_with_gradient(summary["df_os_table"], "Count"))
        render_pie_chart(
            summary["df_os_table"],
            label_col="OS Type",
            value_col="Count",
            title="OS Distribution"
)
        st.write("List of endpoints:")
        st.dataframe(summary["df_endpoints_list"])
    
        output = BytesIO()
        with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
            summary["df_threat_class"].to_excel(writer, sheet_name="Threat_Class", index=False)
            summary["df_threat_endpoints"].to_excel(writer, sheet_name="Threat_Endpoints", index=False)
            summary["df_threat_mit"].to_excel(writer, sheet_name="Threat_Mitigations", index=False)
            summary["df_threat_files"].to_excel(writer, sheet_name="Threat_Files", index=False)  # <--- Threat File Counts
            summary["df_grouped_threats"].to_excel(writer, sheet_name="Threat_Details", index=False)  # <--- Added
            summary["df_vuln_sev"].to_excel(writer, sheet_name="Vuln_Severity", index=False)
            summary["df_vuln_details"].to_excel(writer, sheet_name="Vuln_Details", index=False)
            summary["df_vuln_apps"].to_excel(writer, sheet_name="Vuln_Apps", index=False)
            summary["df_vuln_eps"].to_excel(writer, sheet_name="Vuln_Endpoints", index=False)
            summary["df_hash_summary"].to_excel(writer, sheet_name="Hash_Summary", index=False)
            summary["df_hashes"].to_excel(writer, sheet_name="Hashes", index=False)
            summary["df_sentinel_summary"].to_excel(writer, sheet_name="Sentinel_Summary", index=False)
            summary["df_os_table"].to_excel(writer, sheet_name="OS_Types", index=False)
            summary["df_endpoints_list"].to_excel(writer, sheet_name="Endpoint_List", index=False)
        with col_download:
            st.download_button(
                label=f"⬇️ Download Data for {site_name}",
                data=output.getvalue(),
                file_name=f"{site_name.replace(' ','_')}_Summary.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"dl_btn_{site_name}" # Unique key for each button
            )
    
    # Clear authentication after data fetch to require re-authentication for next fetch
    st.session_state.authenticated_sites = {}
    st.session_state.auth_timestamps = {}
    st.info("🔒 Authentication cleared. Please re-authenticate to fetch data again.")
