import streamlit as st
import requests
import pandas as pd
from datetime import datetime, timezone
from io import BytesIO
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import pyotp
import qrcode
import base64
import re
# --------------------
# CONFIG
# --------------------
SUBDOMAIN = "cybervergent-nfr.alienvault.cloud"
CLIENT_ID = "nascent"
CLIENT_SECRET = "gJk9DVMKgSupgUCY3ggRoAnxT9mV4aHi"
ACCOUNT_NAME = "generic-account" 
# TOTP (Google Authenticator) CONFIGURATION
# We reuse the same secret as the Automation App for convenience
try:
    TOTP_SECRET = st.secrets["general"]["totp_secret"]
except Exception:
    # Fallback or error if secrets are missing
    st.error("❌ Missing secrets.toml configuration for [general] totp_secret")
    st.stop()
    
TOTP_APP_NAME = "AlienVault Extractor"
TOTP_ISSUER = "Esentry Security"
st.set_page_config(page_title="AlienVault Alarm Extractor", layout="wide")
# ========================================
# TOTP AUTHENTICATION GATE (Layer 1 Security)
# ========================================
# Initialize TOTP authentication state
if "totp_authenticated" not in st.session_state:
    st.session_state.totp_authenticated = False
# Check if user has authenticated with TOTP
if not st.session_state.totp_authenticated:
    # Auth Header with Logo
    try:
        with open("s1_logo.png", "rb") as f:
            data = f.read()
            encoded = base64.b64encode(data).decode()
        
        st.markdown(f"""
        <div style="display: flex; align-items: center;">
            <img src="data:image/png;base64,{encoded}" width="50" style="margin-right: 15px;">
            <h1 style="margin: 0; padding: 0;">🔐 AlienVault Extractor - Authentication Required</h1>
        </div>
        """, unsafe_allow_html=True)
    except FileNotFoundError:
        st.title("🔐 AlienVault Extractor - Authentication Required")
    
    # Create TOTP object
    totp = pyotp.TOTP(TOTP_SECRET)
    
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
            if totp.verify(totp_code, valid_window=1):  # Allow 1 time step
                st.session_state.totp_authenticated = True
                st.success("✅ Authentication successful! Redirecting to dashboard...")
                st.rerun()
            else:
                st.error("❌ Invalid code. Please check code in your Authenticator app.")
        else:
            st.warning("⚠️ Please enter a 6-digit code.")
    
    st.stop()  # Stop execution here if not authenticated
# ========================================
# MAIN DASHBOARD (Only accessible after TOTP)
# ========================================
# Header with Logo
col_logo, col_title = st.columns([1, 15])
with col_logo:
    try:
        st.image("s1_logo.png", width=100)
    except Exception:
        pass # Fail gracefully if image missing
with col_title:
    st.title("🚨 AlienVault Alarm Extractor")
st.write("Fetch alarm summaries (and events if available) and export them to Excel with categorized sheets.")
# --- INPUTS ---
col1, col2 = st.columns(2)
with col1:
    start_date = st.date_input("📅 Start Date", value=datetime.now() - pd.Timedelta(days=30))
with col2:
    end_date = st.date_input("📅 End Date", value=datetime.now())
st.info("💡 **Tip**: For faster results, select shorter date ranges (e.g., last 7 or 30 days)")
if start_date > end_date:
    st.error("❌ Start date cannot be after end date.")
    st.stop()
# Calculate date range in days
date_range_days = (end_date - start_date).days
if date_range_days > 365:
    st.warning(f"⚠️ Large date range ({date_range_days} days). This may take longer to fetch.")
def get_token():
    url = f"https://{SUBDOMAIN}/api/2.0/oauth/token"
    data = {"grant_type": "client_credentials"}
    res = requests.post(url, data=data, auth=(CLIENT_ID, CLIENT_SECRET))
    if res.status_code != 200:
        st.error(f"❌ Auth failed ({res.status_code}): {res.text}")
        st.stop()
    return res.json().get("access_token")
def fetch_page(url, headers, params, page_num, response_key, timeout=60):
    """Fetch a single page - used for parallel execution"""
    try:
        page_params = params.copy()
        page_params["page"] = page_num
        r = requests.get(url, headers=headers, params=page_params, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            items = data.get("_embedded", {}).get(response_key, [])
            return items
    except:
        pass
    return []
def fetch_all_parallel(endpoint, params, headers, max_records=100000):
    """
    Ultra-fast parallel fetch with concurrent requests.
    Target: 50K alarms, 1M events in ~20 seconds
    """
    start_time = time.time()
    
    # Map endpoint names to their actual response keys
    response_key_map = {
        "events": "eventResources",
        "alarms": "alarms"
    }
    response_key = response_key_map.get(endpoint, endpoint)
    
    # Set aggressive page size
    params["size"] = 5000  # Max out page size
    params["page"] = 0
    
    url = f"https://{SUBDOMAIN}/api/2.0/{endpoint}"
    
    # First request to get total count
    try:
        r = requests.get(url, headers=headers, params=params, timeout=60)
        if r.status_code != 200:
            st.error(f"❌ Error fetching {endpoint}")
            return []
        
        data = r.json()
        page_info = data.get("page", {})
        total_elements = page_info.get("totalElements", 0)
        total_pages = page_info.get("totalPages", 0)
        
        if total_elements == 0:
            st.info(f"ℹ️ No {endpoint} found")
            return []
        
        # Get first page items
        all_data = data.get("_embedded", {}).get(response_key, [])
        
    except Exception as e:
        st.error(f"❌ Error: {str(e)}")
        return []
    
    # Calculate pages to fetch
    records_per_page = params.get("size", 5000)
    max_pages_needed = min(total_pages, (max_records // records_per_page) + 1, 200)
    
    if max_pages_needed <= 1:
        st.success(f"✅ Fetched {len(all_data):,} {endpoint} ({time.time()-start_time:.1f}s)")
        return all_data
    
    # Show what we're fetching
    will_fetch = min(total_elements, max_records)
    if total_elements > max_records:
        st.warning(f"⚠️ Found {total_elements:,} {endpoint}, fetching {max_records:,} most recent")
    else:
        st.info(f"📊 Fetching {total_elements:,} {endpoint} across {max_pages_needed} pages...")
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Parallel fetch remaining pages
    # Use 10 concurrent workers for aggressive parallelization
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Submit all page fetch jobs
        future_to_page = {
            executor.submit(fetch_page, url, headers, params, page_num, response_key): page_num
            for page_num in range(1, max_pages_needed)
        }
        
        completed = 0
        for future in as_completed(future_to_page):
            items = future.result()
            if items:
                all_data.extend(items)
            
            completed += 1
            progress = completed / (max_pages_needed - 1)
            progress_bar.progress(min(progress, 1.0))
            status_text.text(f"⚡ Fetched {len(all_data):,} / {will_fetch:,} {endpoint}... ({time.time()-start_time:.1f}s)")
            
            if len(all_data) >= max_records:
                break
    
    # Clear progress
    progress_bar.empty()
    status_text.empty()
    
    elapsed = time.time() - start_time
    st.success(f"✅ Fetched {len(all_data):,} {endpoint} in {elapsed:.1f} seconds")
    
    return all_data[:max_records]  # Ensure we don't exceed limit
if st.button("🚀 Fetch Alarms"):
    with st.spinner("Fetching data from AlienVault..."):
        start_dt = datetime.combine(start_date, datetime.min.time()).replace(tzinfo=timezone.utc)
        end_dt = datetime.combine(end_date, datetime.max.time()).replace(tzinfo=timezone.utc)
        start_ms = int(start_dt.timestamp() * 1000)
        end_ms = int(end_dt.timestamp() * 1000)
        token = get_token()
        headers = {"Authorization": f"Bearer {token}"}
        # Fetch alarms in parallel (up to 50K)
        st.subheader("📥 Fetching Alarms...")
        alarms = fetch_all_parallel("alarms", {
             "timestamp_received_gte": start_ms,
             "timestamp_received_lte": end_ms,
             "sort": "timestamp_received,desc",
             "suppressed": False,
             "status": ["open", "closed", "in_review"] # Match UI "Alarm Status" filter
        }, headers, max_records=50000)
        # Fetch events in parallel (up to 1M)
        st.subheader("📥 Fetching Events...")
        events = fetch_all_parallel("events", {
             "timestamp_received_gte": start_ms,
             "timestamp_received_lte": end_ms,
             "sort": "timestamp_received,desc"
        }, headers, max_records=1000000)
        if not alarms and not events:
            st.warning("⚠️ No alarms or events found for the selected period.")
        else:
            # --- PROCESS ALARMS ---
            if alarms:
                df_alarms = pd.json_normalize(alarms)
                # --- COMPUTE ALARM SUMMARIES ---
                top_methods = df_alarms['rule_method'].value_counts().head(30).reset_index()
                top_methods.columns = ['Method', 'Count']
                top_methods = top_methods.sort_values(by='Count', ascending=False)
            else:
                df_alarms = pd.DataFrame()
                top_methods = pd.DataFrame(columns=['Method', 'Count'])
                top_strategy = pd.DataFrame(columns=['Strategy', 'Count'])
                top_intent = pd.DataFrame(columns=['Intent', 'Count'])
                failed_logons_df = pd.DataFrame(columns=['Failed Logon Type', 'Count'])
                user_activities_df = pd.DataFrame(columns=['Activity', 'Count'])
                unlocked_users = pd.DataFrame(columns=['Username', 'Count'])
                disabled_users = pd.DataFrame(columns=['Username', 'Count'])
                severity_df = pd.DataFrame(columns=['Severity', 'Count'])
            if alarms:
                top_strategy = df_alarms['rule_strategy'].value_counts().head(30).reset_index()
                top_strategy.columns = ['Strategy', 'Count']
                top_strategy = top_strategy.sort_values(by='Count', ascending=False)
                top_intent = df_alarms['rule_intent'].value_counts().head(30).reset_index()
                top_intent.columns = ['Intent', 'Count']
                top_intent = top_intent.sort_values(by='Count', ascending=False)
                failed_logons = {
                    'Nonexistent Account': len(df_alarms[df_alarms['rule_method'] == 'Failed Logon to Nonexistent Account']),
                    'Default Account': len(df_alarms[df_alarms['rule_method'] == 'Failed Logon to Default Account']),
                    'Disabled Account': len(df_alarms[df_alarms['rule_method'] == 'Failed Logon to Disabled Account'])
                }
                failed_logons_df = pd.DataFrame(list(failed_logons.items()), columns=['Failed Logon Type', 'Count']).sort_values(by='Count', ascending=False)
                user_activities = {
                    'User Account was Unlocked': len(df_alarms[df_alarms['rule_method'] == 'User Account was Unlocked']),
                    'A User Account was Disabled': len(df_alarms[df_alarms['rule_method'] == 'A User Account was Disabled']),
                    'User added to Admin role': len(df_alarms[df_alarms['rule_method'] == 'User added to Admin role']),
                    'User Added to Enterprise Admins Group': len(df_alarms[df_alarms['rule_method'] == 'User Added to Enterprise Admins Group']),
                    'Create User': len(df_alarms[df_alarms['rule_method'] == 'Create User']),
                    'User Added to Local Administrators Group': len(df_alarms[df_alarms['rule_method'] == 'User Added to Local Administrators Group']),
                }
                user_activities_df = pd.DataFrame(list(user_activities.items()), columns=['Activity', 'Count']).sort_values(by='Count', ascending=False)
                unlocked_users = df_alarms[df_alarms['rule_method'] == 'User Account was Unlocked']['source_username'].value_counts().reset_index()
                unlocked_users.columns = ['Username', 'Count']
                disabled_users = df_alarms[df_alarms['rule_method'] == 'A User Account was Disabled']['source_username'].value_counts().reset_index()
                disabled_users.columns = ['Username', 'Count']
                severity_df = df_alarms['priority_label'].value_counts().reset_index()
                severity_df.columns = ['Severity', 'Count']
                severity_df = severity_df.sort_values(by='Count', ascending=False)
            # --- PROCESS EVENTS ---
            if events:
                df_events = pd.json_normalize(events)
                
                # Extract unique sensors - try multiple possible field names
                sensor_field = None
                possible_sensor_fields = ['sensor', 'data_source', 'source_name', 'plugin', 'sensor_name']
                
                for field in possible_sensor_fields:
                    if field in df_events.columns:
                        sensor_field = field
                        st.info(f"✅ Found sensor field: `{sensor_field}`")
                        break
                
                if sensor_field:
                    unique_sensors = df_events[sensor_field].unique()
                    sensor_list = pd.DataFrame({'Sensor Name': unique_sensors})
                    st.info(f"📡 Found {len(unique_sensors)} unique sensors in event data")
                else:
                    sensor_list = pd.DataFrame(columns=['Sensor Name'])
                    st.warning("⚠️ No sensor field found. Tried: " + ", ".join(possible_sensor_fields))
                
                # Extract top 20 event names overall
                if 'event_name' in df_events.columns:
                    top_event_names = df_events['event_name'].value_counts().head(20).reset_index()
                    top_event_names.columns = ['Event Name', 'Count']
                    top_event_names = top_event_names.sort_values(by='Count', ascending=False)
                else:
                    top_event_names = pd.DataFrame(columns=['Event Name', 'Count'])
                
                # Extract top 20 event names by sensor
                events_by_sensor = {}
                if sensor_field and 'event_name' in df_events.columns:
                    for sensor in unique_sensors:
                        sensor_events = df_events[df_events[sensor_field] == sensor]
                        top_events_for_sensor = sensor_events['event_name'].value_counts().head(20).reset_index()
                        top_events_for_sensor.columns = ['Event Name', 'Count']
                        events_by_sensor[sensor] = top_events_for_sensor
            else:
                df_events = pd.DataFrame()
                top_event_names = pd.DataFrame(columns=['Event Name', 'Count'])
                sensor_list = pd.DataFrame(columns=['Sensor Name'])
                events_by_sensor = {}
            # --- DISPLAY DATA ---
            st.subheader("📊 Top 30 Alarms by Method")
            st.dataframe(top_methods)
            st.subheader("📊 Top 30 Alarms by Strategy")
            st.dataframe(top_strategy)
            st.subheader("📊 Top 30 Alarms by Intent")
            st.dataframe(top_intent)
            st.subheader("🚫 Failed Logons Summary")
            st.dataframe(failed_logons_df)
            st.subheader("👥 User Activities Summary")
            st.dataframe(user_activities_df)
            st.subheader("🔓 Usernames - Unlocked Accounts")
            st.dataframe(unlocked_users)
            st.subheader("❌ Usernames - Disabled Accounts")
            st.dataframe(disabled_users)
            st.subheader("⚠️ Alarms by Severity")
            st.dataframe(severity_df)
            # --- DISPLAY EVENTS DATA ---
            if events:
                st.write("---")
                st.header("📋 Events Analysis")
                
                st.subheader("📡 Available Sensors")
                st.dataframe(sensor_list)
                
                st.subheader("📊 Top 20 Event Names (Overall)")
                st.dataframe(top_event_names)
                
                # Display top 20 events by sensor
                if events_by_sensor:
                    st.subheader("📊 Top 20 Event Names by Sensor")
                    for sensor, sensor_df in events_by_sensor.items():
                        with st.expander(f"🔍 Sensor: {sensor}"):
                            st.dataframe(sensor_df)
            # --- EXPORT TO EXCEL ---
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                # Alarm sheets
                top_methods.to_excel(writer, index=False, sheet_name='Top 30 Methods')
                top_strategy.to_excel(writer, index=False, sheet_name='Top 30 Strategy')
                top_intent.to_excel(writer, index=False, sheet_name='Top 30 Intent')
                failed_logons_df.to_excel(writer, index=False, sheet_name='Failed Logons')
                user_activities_df.to_excel(writer, index=False, sheet_name='User Activities')
                unlocked_users.to_excel(writer, index=False, sheet_name='Unlocked Accounts')
                disabled_users.to_excel(writer, index=False, sheet_name='Disabled Accounts')
                severity_df.to_excel(writer, index=False, sheet_name='Alarms by Severity')
                
                # Event sheets (if events exist)
                if events:
                    sensor_list.to_excel(writer, index=False, sheet_name='Sensors List')
                    top_event_names.to_excel(writer, index=False, sheet_name='Top 20 Events Overall')
                    
                    # Create a sheet for each sensor's top events
                    for sensor, sensor_df in events_by_sensor.items():
                        # Sanitize sheet name (max 31 chars, no special chars)
                        sheet_name = f"Events_{sensor}"[:31].replace('/', '_').replace('\\', '_')
                        sensor_df.to_excel(writer, index=False, sheet_name=sheet_name)
            st.download_button(
                label="⬇️ Download Full Report (Excel)",
                data=output.getvalue(),
                file_name=f"alarms_summary_{start_date}_to_{end_date}.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )
