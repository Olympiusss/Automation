"""
SOC Agent — Centralized Configuration
All settings for the SentinelOne Agentic SOC system.
"""

import os

# ─────────────────────────────────────────────
# SentinelOne Platform
# ─────────────────────────────────────────────
S1_BASE_URL = os.environ.get(
    "S1_BASE_URL",
    "https://euce1-exclusive.sentinelone.net/web/api/v2.1"
)
S1_API_TOKEN = os.environ.get("S1_API_TOKEN", "")

# Rate-limit safety
S1_REQUEST_TIMEOUT = 30
S1_RATE_LIMIT_RETRY_DELAY = 2
S1_MAX_RETRIES = 3
S1_PAGE_SIZE = 200
S1_PAGINATION_DELAY = 0.05  # seconds between paginated calls

# ─────────────────────────────────────────────
# Monitoring Daemon
# ─────────────────────────────────────────────
MONITOR_CONFIG = {
    "poll_interval_seconds": 30,
    "severity_thresholds": ["Critical", "High"],
    "lookback_seconds": 60,
    "max_tickets_per_hour": 30,
    "site_cache_ttl_seconds": 300,
    "state_file": "monitor_state.json",
    "log_file": "monitor_log.json",
}

# ─────────────────────────────────────────────
# LLM Providers
# ─────────────────────────────────────────────# LLM Engine Configuration
LLM_CONFIG = {
    # Primary: Anthropic Claude (handles tool execution best)
    "claude_model": "claude-3-5-haiku-20241022",
    "claude_model_heavy": "claude-3-5-sonnet-20241022",
    "claude_api_key": os.environ.get("ANTHROPIC_API_KEY", ""),

    # Fallback/Secondary: HuggingFace (Free alternatives)
    "hf_model": "meta-llama/Llama-3.3-70B-Instruct",
    "hf_api_key": os.environ.get("HF_TOKEN", ""),

    # Generation params
    "temperature": 0.1,
    "max_tokens": 4096,
    "max_react_steps": 10,
}

# ─────────────────────────────────────────────
# Zoho Desk
# ─────────────────────────────────────────────
ZOHO_CONFIG = {
    "accounts_url": os.environ.get("ZOHO_ACCOUNTS_URL", "https://accounts.zoho.com"),
    "desk_url": os.environ.get("ZOHO_DESK_URL", "https://desk.zoho.com/api/v1"),
    "client_id": os.environ.get("ZOHO_CLIENT_ID", ""),
    "client_secret": os.environ.get("ZOHO_CLIENT_SECRET", ""),
    "refresh_token": os.environ.get("ZOHO_REFRESH_TOKEN", ""),
    "org_id": os.environ.get("ZOHO_ORG_ID", ""),
    "department_id": os.environ.get("ZOHO_DEPARTMENT_ID", ""),
}

# Severity → Zoho Priority mapping
SEVERITY_TO_PRIORITY = {
    "Critical": "Urgent",
    "High": "High",
    "Medium": "Medium",
    "Low": "Low",
}

# ─────────────────────────────────────────────
# MS Teams Notifications
# ─────────────────────────────────────────────
TEAMS_WEBHOOK_URL = os.environ.get("TEAMS_WEBHOOK_URL", "")

# Severity → Adaptive Card accent color
SEVERITY_COLORS = {
    "Critical": "attention",   # red
    "High": "warning",         # orange/yellow
    "Medium": "accent",        # blue
    "Low": "good",             # green
}


def load_from_streamlit_secrets():
    """Load settings from Streamlit secrets if running in Streamlit."""
    global S1_API_TOKEN, S1_BASE_URL, ZOHO_CONFIG, TEAMS_WEBHOOK_URL
    
    try:
        import streamlit as st
        if not st.secrets:
            return
            
        general = st.secrets.get("general", {})
        zoho = st.secrets.get("zoho", {})
        teams = st.secrets.get("teams", {})
        
        # S1 Settings
        S1_API_TOKEN = general.get("api_token", S1_API_TOKEN)
        S1_BASE_URL = general.get("base_url", S1_BASE_URL)
        
        # Zoho
        ZOHO_CONFIG["client_id"] = zoho.get("client_id", "")
        ZOHO_CONFIG["client_secret"] = zoho.get("client_secret", "")
        ZOHO_CONFIG["refresh_token"] = zoho.get("refresh_token", "")
        ZOHO_CONFIG["org_id"] = zoho.get("org_id", "")
        ZOHO_CONFIG["department_id"] = zoho.get("department_id", "")
        
        # Teams
        TEAMS_WEBHOOK_URL = teams.get("webhook_url", TEAMS_WEBHOOK_URL)
        
        # LLM Integrations
        LLM_CONFIG["claude_api_key"] = general.get("claude_api_key", LLM_CONFIG["claude_api_key"])
        LLM_CONFIG["hf_api_key"] = general.get("hf_api_key", LLM_CONFIG["hf_api_key"])

    except Exception:
        pass  # Not running in Streamlit — use env vars
