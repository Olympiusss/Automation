import requests
import pandas as pd
from datetime import datetime, timezone

# --- CONFIG ---
SUBDOMAIN = "cybervergent-nfr.alienvault.cloud"
CLIENT_ID = "nascent"
CLIENT_SECRET = "gJk9DVMKgSupgUCY3ggRoAnxT9mV4aHi"

def get_token():
    url = f"https://{SUBDOMAIN}/api/2.0/oauth/token"
    data = {"grant_type": "client_credentials"}
    res = requests.post(url, data=data, auth=(CLIENT_ID, CLIENT_SECRET))
    if res.status_code != 200:
        print(f"❌ Auth failed ({res.status_code}): {res.text}")
        return None
    return res.json().get("access_token")

def fetch_events(token):
    url = f"https://{SUBDOMAIN}/api/2.0/events"
    headers = {"Authorization": f"Bearer {token}"}
    
    # Fetch recent 10 events
    params = {
        "size": 10,
        "sort": "timestamp_occured,desc"
    }
    
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        print(f"❌ Error fetching events: {r.text}")
        return None
    
    data = r.json()
    events = data.get("_embedded", {}).get("eventResources", [])
    return events

if __name__ == "__main__":
    print("=" * 80)
    print("EVENT COLUMNS DIAGNOSTIC TOOL")
    print("=" * 80)
    
    # Get token
    print("\n1. Getting authentication token...")
    token = get_token()
    if not token:
        exit(1)
    print("✅ Token obtained")
    
    # Fetch events
    print("\n2. Fetching recent 10 events...")
    events = fetch_events(token)
    if not events:
        print("❌ No events found")
        exit(1)
    print(f"✅ Fetched {len(events)} events")
    
    # Convert to DataFrame
    df = pd.json_normalize(events)
    
    # Display all columns
    print("\n" + "=" * 80)
    print("ALL EVENT COLUMNS:")
    print("=" * 80)
    for i, col in enumerate(df.columns, 1):
        print(f"{i:3d}. {col}")
    
    # Show sample data for columns that might be sensor-related
    print("\n" + "=" * 80)
    print("SAMPLE DATA FOR POTENTIAL SENSOR FIELDS:")
    print("=" * 80)
    
    sensor_related = [col for col in df.columns if any(word in col.lower() 
                      for word in ['sensor', 'source', 'plugin', 'data'])]
    
    for col in sensor_related:
        print(f"\n📌 Column: {col}")
        print(f"   Sample values: {df[col].head(3).tolist()}")
        print(f"   Unique count: {df[col].nunique()}")
    
    print("\n" + "=" * 80)
    print("COMPLETED")
    print("=" * 80)
