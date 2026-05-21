"""
SentinelOne AI Agent — ChatGPT-Style Interface
Username/Password + TOTP 2FA → Premium dark-themed chat with settings
"""

import streamlit as st
import json
import uuid
import hashlib
import os
import time
import pyotp
import qrcode
import base64
import shutil
from io import BytesIO
from datetime import datetime, timedelta
from PIL import Image

# --- Constants ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CHAT_HISTORY_DIR = os.path.join(APP_DIR, "chat_history")
USER_DATA_DIR = os.path.join(APP_DIR, "user_data")
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_DURATION_SECONDS = 60

# Ensure directories exist
os.makedirs(CHAT_HISTORY_DIR, exist_ok=True)
os.makedirs(USER_DATA_DIR, exist_ok=True)

# --- Page Config (MUST be first Streamlit call) ---
st.set_page_config(
    page_title="Sentry Agentic",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Imports (after page config) ---
from sentinelone_api import fetch_sites

try:
    from agent_llm import process_user_query, get_available_provider
    AGENT_AVAILABLE = True
    _IMPORT_ERROR = None
except Exception as e:
    AGENT_AVAILABLE = False
    _IMPORT_ERROR = f"{type(e).__name__}: {e}"
    process_user_query = None
    get_available_provider = None

# Import free models list separately so it doesn't break everything
try:
    from agent_llm import OPENROUTER_FREE_MODELS
except ImportError:
    OPENROUTER_FREE_MODELS = [
        {"id": "meta-llama/llama-3.3-70b-instruct:free",       "name": "Llama 3.3 70B (Free)",      "tier": "high"},
        {"id": "google/gemma-3-27b-it:free",                   "name": "Gemma 3 27B (Free)",        "tier": "high"},
        {"id": "deepseek/deepseek-chat-v3-0324:free",          "name": "DeepSeek V3 (Free)",        "tier": "high"},
        {"id": "deepseek/deepseek-r1-0528:free",               "name": "DeepSeek R1 (Free)",        "tier": "high"},
        {"id": "qwen/qwen3-32b:free",                          "name": "Qwen 3 32B (Free)",         "tier": "medium"},
        {"id": "mistralai/mistral-small-3.1-24b-instruct:free","name": "Mistral Small 3.1 (Free)",  "tier": "medium"},
    ]


# ============================================
# Theme Presets
# ============================================
THEME_PRESETS = {
    "Dark": {
        "bg_primary": "#212121",
        "bg_secondary": "#171717",
        "bg_tertiary": "#2f2f2f",
        "bg_input": "#303030",
        "border": "#444",
        "text_primary": "#ECECEC",
        "text_secondary": "#9a9a9a",
        "accent": "#10a37f",
        "accent_hover": "#1a7f64",
        "user_bubble": "#2e7d5b",
        "user_bubble_text": "#FFFFFF",
        "assistant_bg": "transparent",
        "sidebar_active": "#2a2a2a",
    },
    "Midnight Blue": {
        "bg_primary": "#1a1b2e",
        "bg_secondary": "#12132a",
        "bg_tertiary": "#252742",
        "bg_input": "#2a2c4a",
        "border": "#3a3c5a",
        "text_primary": "#E8E8F0",
        "text_secondary": "#8888aa",
        "accent": "#6C63FF",
        "accent_hover": "#5a52e0",
        "user_bubble": "#4a42d4",
        "user_bubble_text": "#FFFFFF",
        "assistant_bg": "transparent",
        "sidebar_active": "#252742",
    },
    "Forest Green": {
        "bg_primary": "#1a2420",
        "bg_secondary": "#121c18",
        "bg_tertiary": "#243830",
        "bg_input": "#2a3e34",
        "border": "#3a5a48",
        "text_primary": "#E0F0E8",
        "text_secondary": "#88aa98",
        "accent": "#4CAF50",
        "accent_hover": "#388E3C",
        "user_bubble": "#2e7d32",
        "user_bubble_text": "#FFFFFF",
        "assistant_bg": "transparent",
        "sidebar_active": "#243830",
    },
    "Deep Purple": {
        "bg_primary": "#1e1a2e",
        "bg_secondary": "#161228",
        "bg_tertiary": "#2e2842",
        "bg_input": "#362f50",
        "border": "#4a3f6a",
        "text_primary": "#EDE8F5",
        "text_secondary": "#9a8ab8",
        "accent": "#BB86FC",
        "accent_hover": "#9b66dc",
        "user_bubble": "#7c4dff",
        "user_bubble_text": "#FFFFFF",
        "assistant_bg": "transparent",
        "sidebar_active": "#2e2842",
    },
}


def _build_css(theme_name: str = "Dark") -> str:
    """Build premium, high-end CSS from a theme preset."""
    t = THEME_PRESETS.get(theme_name, THEME_PRESETS["Dark"])
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

/* --- Global Styles --- */
.stApp {{
    background-color: {t["bg_primary"]} !important;
    color: {t["text_primary"]} !important;
    font-family: 'Inter', sans-serif !important;
    -webkit-font-smoothing: antialiased;
}}
header[data-testid="stHeader"] {{
    background-color: transparent !important;
    backdrop-filter: blur(8px);
}}
div[data-testid="stToolbar"] {{
    display: none !important;
}}

/* --- Sidebar Styling --- */
section[data-testid="stSidebar"] {{
    background-color: {t["bg_secondary"]} !important;
    border-right: 1px solid {t["border"]} !important;
    box-shadow: 4px 0 24px rgba(0, 0, 0, 0.2);
}}
section[data-testid="stSidebar"] .stMarkdown,
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] label {{
    color: {t["text_primary"]} !important;
    font-family: 'Inter', sans-serif !important;
}}

/* --- Premium Buttons --- */
.stButton > button {{
    background-color: rgba(255, 255, 255, 0.03) !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 12px !important;
    padding: 10px 20px !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 13px !important;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05) !important;
}}
.stButton > button:hover {{
    background-color: {t["sidebar_active"]} !important;
    border-color: {t["accent"]} !important;
    transform: translateY(-1px) !important;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15), 0 0 8px rgba(16, 163, 127, 0.2) !important;
}}

/* New Chat Button Accent */
.new-chat-btn > button {{
    background: linear-gradient(135deg, {t["accent"]} 0%, {t["accent_hover"]} 100%) !important;
    color: #FFFFFF !important;
    border: none !important;
    font-weight: 600 !important;
    letter-spacing: 0.5px !important;
    box-shadow: 0 4px 15px rgba(16, 163, 127, 0.3) !important;
}}
.new-chat-btn > button:hover {{
    transform: translateY(-1.5px) !important;
    box-shadow: 0 6px 20px rgba(16, 163, 127, 0.45) !important;
}}

/* Active Chat Highlight */
.active-chat > button {{
    background-color: {t["sidebar_active"]} !important;
    border-color: {t["accent"]} !important;
    font-weight: 600 !important;
}}

/* --- Chat Messages --- */
div[data-testid="stChatMessage"] {{
    border-radius: 18px !important;
    padding: 16px 20px !important;
    margin-bottom: 12px !important;
    max-width: 85% !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 14.5px !important;
    line-height: 1.6 !important;
    box-shadow: 0 4px 15px rgba(0,0,0,0.05) !important;
    border: 1px solid rgba(255, 255, 255, 0.03) !important;
}}

/* User Chat Message Bubble */
div[data-testid="stChatMessage"]:has(div[data-testid="stChatMessageContent"]):has(span:contains("You")),
div[data-testid="stChatMessage"][data-testid="user-message"] {{
    background-color: {t["user_bubble"]} !important;
    color: {t["user_bubble_text"]} !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
}}

/* --- Chat Input Area --- */
div[data-testid="stChatInput"] {{
    background-color: {t["bg_input"]} !important;
    border-radius: 28px !important;
    border: 1px solid {t["border"]} !important;
    max-width: 840px !important;
    margin: 0 auto !important;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25) !important;
    transition: all 0.3s ease !important;
}}
div[data-testid="stChatInput"]:focus-within {{
    border-color: {t["accent"]} !important;
    box-shadow: 0 8px 32px rgba(16, 163, 127, 0.15), 0 0 12px rgba(16, 163, 127, 0.25) !important;
}}
div[data-testid="stChatInput"] textarea {{
    color: {t["text_primary"]} !important;
    background-color: transparent !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 14.5px !important;
}}

/* --- Premium Scrollbar --- */
::-webkit-scrollbar {{
    width: 6px;
    height: 6px;
}}
::-webkit-scrollbar-track {{
    background: transparent;
}}
::-webkit-scrollbar-thumb {{
    background: {t["border"]};
    border-radius: 10px;
}}
::-webkit-scrollbar-thumb:hover {{
    background: {t["accent"]};
}}

/* --- Premium Cyberpunk Logo/Header --- */
.logo-wrapper {{
    position: relative;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 72px;
    height: 72px;
    margin-bottom: 24px;
}}
.logo-glow {{
    position: absolute;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle, {t["accent"]} 0%, transparent 70%);
    opacity: 0.35;
    filter: blur(10px);
    animation: pulse 3s infinite ease-in-out;
}}
@keyframes pulse {{
    0%, 100% {{ transform: scale(1); opacity: 0.25; }}
    50% {{ transform: scale(1.15); opacity: 0.45; }}
}}
.logo-inner {{
    position: relative;
    background: linear-gradient(135deg, {t["accent"]} 0%, {t["accent_hover"]} 100%);
    width: 58px;
    height: 58px;
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 8px 24px rgba(16, 163, 127, 0.3);
    border: 1.5px solid rgba(255,255,255,0.15);
}}

/* --- Premium Glass Containers (Login / 2FA) --- */
.login-container {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 50vh;
    text-align: center;
    padding-top: 8vh;
}}
.login-title {{
    color: {t["text_primary"]};
    font-size: 32px;
    font-weight: 700;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
    background: linear-gradient(135deg, #FFFFFF 30%, {t["text_secondary"]} 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    font-family: 'Inter', sans-serif;
}}
.login-subtitle {{
    color: {t["text_secondary"]};
    font-size: 14px;
    font-weight: 400;
    margin-bottom: 36px;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.2px;
}}
.login-form-card {{
    background-color: {t["bg_secondary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 20px !important;
    padding: 36px !important;
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4) !important;
    max-width: 420px;
    margin: 0 auto;
}}

/* --- 2FA Verification Card --- */
.twofa-container {{
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 40vh;
    text-align: center;
    padding-top: 6vh;
}}
.twofa-icon {{
    font-size: 40px;
    margin-bottom: 20px;
    background: linear-gradient(135deg, {t["accent"]} 0%, {t["accent_hover"]} 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}
.twofa-title {{
    color: {t["text_primary"]};
    font-size: 26px;
    font-weight: 700;
    margin-bottom: 8px;
    font-family: 'Inter', sans-serif;
}}
.twofa-subtitle {{
    color: {t["text_secondary"]};
    font-size: 14px;
    margin-bottom: 30px;
    font-family: 'Inter', sans-serif;
}}

/* --- Welcome / Empty State Screen --- */
.main-header {{
    text-align: center;
    padding-top: 18vh;
}}
.main-header h1 {{
    color: {t["text_primary"]} !important;
    font-size: 36px !important;
    font-weight: 700 !important;
    letter-spacing: -0.8px !important;
    font-family: 'Inter', sans-serif !important;
    background: linear-gradient(135deg, #FFFFFF 40%, {t["text_secondary"]} 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}}
.main-header p {{
    color: {t["text_secondary"]} !important;
    font-size: 15px !important;
    margin-top: 12px !important;
}}

/* --- Settings Panel Cards --- */
.settings-card {{
    background-color: {t["bg_tertiary"]};
    border: 1px solid {t["border"]};
    border-radius: 18px;
    padding: 28px;
    margin-bottom: 20px;
    box-shadow: 0 6px 16px rgba(0,0,0,0.1);
}}
.settings-title {{
    color: {t["text_primary"]};
    font-size: 17px;
    font-weight: 600;
    margin-bottom: 16px;
    font-family: 'Inter', sans-serif;
}}

/* --- Profile Avatars --- */
.profile-section {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 10px 0;
}}
.profile-avatar {{
    width: 38px;
    height: 38px;
    border-radius: 50%;
    object-fit: cover;
    border: 2px solid {t["accent"]};
    box-shadow: 0 0 10px rgba(16, 163, 127, 0.3);
}}
.profile-avatar-large {{
    width: 84px;
    height: 84px;
    border-radius: 50%;
    object-fit: cover;
    border: 3px solid {t["accent"]};
    box-shadow: 0 0 16px rgba(16, 163, 127, 0.4);
}}

/* --- Chat Date Categories --- */
.chat-date-label {{
    color: {t["text_secondary"]};
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    padding: 12px 8px 6px 8px;
    margin-top: 12px;
    font-family: 'Inter', sans-serif;
}}

/* --- Premium Settings Tabs --- */
.stTabs [data-baseweb="tab-list"] {{
    background-color: rgba(0,0,0,0.15) !important;
    gap: 6px !important;
    border-radius: 12px !important;
    padding: 4px !important;
    border: 1px solid {t["border"]} !important;
}}
.stTabs [data-baseweb="tab"] {{
    background-color: transparent !important;
    color: {t["text_secondary"]} !important;
    border-radius: 8px !important;
    border: none !important;
    padding: 8px 24px !important;
    font-family: 'Inter', sans-serif !important;
    font-weight: 500 !important;
    font-size: 13px !important;
    transition: all 0.2s ease !important;
}}
.stTabs [aria-selected="true"] {{
    background-color: {t["accent"]} !important;
    color: #FFFFFF !important;
    box-shadow: 0 4px 10px rgba(16, 163, 127, 0.2) !important;
}}

/* Inputs, Textareas, Selectboxes */
.stTextInput input, .stTextArea textarea, .stSelectbox > div > div {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 12px !important;
    font-family: 'Inter', sans-serif !important;
    transition: border-color 0.2s ease !important;
}}
.stTextInput input:focus, .stTextArea textarea:focus {{
    border-color: {t["accent"]} !important;
}}
.stTextInput label, .stTextArea label, .stSelectbox label {{
    color: {t["text_secondary"]} !important;
    font-weight: 500 !important;
}}

/* File Uploaders */
div[data-testid="stFileUploader"] {{
    background-color: rgba(255, 255, 255, 0.02) !important;
    border: 1px dashed {t["border"]} !important;
    border-radius: 14px !important;
    padding: 16px !important;
}}

/* Expanders */
.streamlit-expanderHeader {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border-radius: 10px !important;
    border: 1px solid {t["border"]} !important;
    font-weight: 500 !important;
}}

/* --- Notification Toast --- */
.share-toast {{
    position: fixed;
    bottom: 80px;
    left: 50%;
    transform: translateX(-50%);
    background: {t["accent"]};
    color: #FFFFFF;
    padding: 12px 28px;
    border-radius: 12px;
    font-weight: 500;
    box-shadow: 0 8px 24px rgba(16, 163, 127, 0.4);
    font-size: 14px;
    z-index: 9999;
    animation: fadeOut 2.5s cubic-bezier(0.4, 0, 0.2, 1) forwards;
}}
@keyframes fadeOut {{
    0% {{ opacity: 0; transform: translate(-50%, 10px); }}
    15% {{ opacity: 1; transform: translate(-50%, 0); }}
    85% {{ opacity: 1; }}
    100% {{ opacity: 0; transform: translate(-50%, -10px); }}
}}
</style>
"""


# ============================================
# User Data Helpers
# ============================================
def _user_dir(username: str) -> str:
    """Get/create per-user data directory."""
    d = os.path.join(USER_DATA_DIR, hashlib.md5(username.encode()).hexdigest()[:12])
    os.makedirs(d, exist_ok=True)
    os.makedirs(os.path.join(d, "uploads"), exist_ok=True)
    return d


def load_user_profile(username: str) -> dict:
    """Load user profile (theme, avatar path)."""
    path = os.path.join(_user_dir(username), "profile.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {"theme": "Dark", "avatar_path": None}


def save_user_profile(username: str, profile: dict):
    """Save user profile."""
    path = os.path.join(_user_dir(username), "profile.json")
    with open(path, "w") as f:
        json.dump(profile, f, indent=2)


def get_avatar_path(username: str) -> str | None:
    """Get the avatar file path if it exists."""
    user_d = _user_dir(username)
    for ext in ["png", "jpg", "jpeg", "webp"]:
        p = os.path.join(user_d, f"avatar.{ext}")
        if os.path.exists(p):
            return p
    return None


def save_avatar(username: str, uploaded_file) -> str:
    """Save uploaded avatar and return path."""
    user_d = _user_dir(username)
    # Remove old avatars
    for ext in ["png", "jpg", "jpeg", "webp"]:
        old = os.path.join(user_d, f"avatar.{ext}")
        if os.path.exists(old):
            os.remove(old)
    # Save new
    file_ext = uploaded_file.name.rsplit(".", 1)[-1].lower()
    if file_ext not in ["png", "jpg", "jpeg", "webp"]:
        file_ext = "png"
    path = os.path.join(user_d, f"avatar.{file_ext}")
    with open(path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return path


def load_password_overrides() -> dict:
    """Load password overrides from JSON."""
    path = os.path.join(USER_DATA_DIR, "passwords.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_password_override(username: str, new_hash: str):
    """Save a password override."""
    overrides = load_password_overrides()
    overrides[username.lower()] = new_hash
    path = os.path.join(USER_DATA_DIR, "passwords.json")
    with open(path, "w") as f:
        json.dump(overrides, f, indent=2)


def save_chat_image(username: str, uploaded_file) -> str:
    """Save an uploaded chat image and return its path."""
    user_d = _user_dir(username)
    uploads_dir = os.path.join(user_d, "uploads")
    file_ext = uploaded_file.name.rsplit(".", 1)[-1].lower()
    filename = f"{uuid.uuid4().hex[:8]}.{file_ext}"
    path = os.path.join(uploads_dir, filename)
    with open(path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    return path


# ============================================
# Auth Helpers
# ============================================
def hash_password(password: str) -> str:
    """Hash a password with SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(input_password: str, stored_value: str) -> bool:
    """Verify a password against a stored value (hash or plaintext)."""
    if not stored_value:
        return False
    # If it looks like a SHA-256 hash (64 hex chars), compare as hash
    if len(stored_value) == 64 and all(c in '0123456789abcdef' for c in stored_value.lower()):
        return hash_password(input_password) == stored_value
    # Otherwise treat as plaintext password
    return input_password == stored_value


def get_users() -> dict:
    """Load users from Streamlit secrets, with JSON password overrides merged in."""
    try:
        users_section = st.secrets["agent_users"]
        result = {}
        for key in users_section:
            val = users_section[key]
            if hasattr(val, "keys"):
                result[key] = dict(val)
            else:
                result[key] = val

        # Merge password overrides
        overrides = load_password_overrides()
        for uname, user_data in result.items():
            if isinstance(user_data, dict):
                override_key = uname.lower()
                if override_key in overrides:
                    user_data["password_hash"] = overrides[override_key]
        return result
    except KeyError:
        return {}
    except Exception:
        return {}


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code against the user's secret."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def generate_qr_code_base64(username: str, totp_secret: str) -> str:
    """Generate a QR code image as a base64 string for Google Authenticator."""
    totp = pyotp.TOTP(totp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name="SentinelOne Agent")
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()


# ============================================
# Chat Persistence (JSON file per user)
# ============================================
def _get_chat_file(username: str) -> str:
    """Get the path to a user's chat history file."""
    os.makedirs(CHAT_HISTORY_DIR, exist_ok=True)
    safe_name = hashlib.md5(username.encode()).hexdigest()[:12]
    return os.path.join(CHAT_HISTORY_DIR, f"{safe_name}.json")


def save_chats(username: str, chats: dict, active_chat_id: str = None):
    """Save user's chats to a JSON file."""
    data = {
        "chats": {},
        "active_chat_id": active_chat_id
    }
    for chat_id, chat_data in chats.items():
        data["chats"][chat_id] = {
            "title": chat_data.get("title", "New chat"),
            "messages": chat_data.get("messages", []),
            "created_at": chat_data.get("created_at", datetime.now().isoformat())
        }
    path = _get_chat_file(username)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_chats(username: str) -> tuple:
    """Load user's chats from JSON file. Returns (chats_dict, active_chat_id)."""
    path = _get_chat_file(username)
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("chats", {}), data.get("active_chat_id")
    except Exception:
        return {}, None


# ============================================
# Login Attempt Tracking
# ============================================
@st.cache_resource
def _get_login_tracker():
    """Return a shared dict to track login attempts across sessions."""
    return {}


def check_lockout(username: str):
    """Check if a user is locked out. Returns (is_locked, seconds_remaining)."""
    tracker = _get_login_tracker()
    key = username.lower()
    if key not in tracker:
        return False, 0
    info = tracker[key]
    if info.get("locked_until"):
        remaining = info["locked_until"] - time.time()
        if remaining > 0:
            return True, int(remaining)
        else:
            tracker.pop(key, None)
            return False, 0
    return False, 0


def record_failed_attempt(username: str) -> bool:
    """Record a failed login attempt. Returns True if now locked out."""
    tracker = _get_login_tracker()
    key = username.lower()
    if key not in tracker:
        tracker[key] = {"attempts": 0}
    tracker[key]["attempts"] = tracker[key].get("attempts", 0) + 1
    if tracker[key]["attempts"] >= MAX_LOGIN_ATTEMPTS:
        tracker[key]["locked_until"] = time.time() + LOCKOUT_DURATION_SECONDS
        return True
    return False


def reset_attempts(username: str):
    """Reset login attempts after successful login."""
    tracker = _get_login_tracker()
    tracker.pop(username.lower(), None)


# ============================================
# Session State Initialization
# ============================================
def init_session_state():
    """Initialize all session state variables."""
    defaults = {
        "authenticated": False,
        "auth_step": "login",
        "auth_username": None,
        "user_info": None,
        "chats": {},
        "active_chat_id": None,
        "sites_data": None,
        "provider": None,
        "api_key": None,
        "current_view": "chat",     # "chat" | "settings"
        "user_theme": "Dark",
        "pending_image": None,
        "selected_model_id": None,   # OpenRouter model selection
    }
    for key, val in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = val


def create_new_chat():
    """Create a new chat and set it as active."""
    chat_id = str(uuid.uuid4())[:8]
    st.session_state.chats[chat_id] = {
        "title": "New chat",
        "messages": [],
        "created_at": datetime.now().isoformat()
    }
    st.session_state.active_chat_id = chat_id
    return chat_id


def get_active_chat():
    """Get the currently active chat, or create one if none exists."""
    if not st.session_state.active_chat_id or st.session_state.active_chat_id not in st.session_state.chats:
        create_new_chat()
    return st.session_state.chats[st.session_state.active_chat_id]


def generate_chat_title(message: str) -> str:
    """Generate a short title from the first message."""
    title = message.strip()[:50]
    if len(message) > 50:
        title += "…"
    return title


# ============================================
# Login Page — Step 1: Username + Password
# ============================================
def render_login_page():
    """Render the username/password login screen with premium styling."""
    st.markdown("""
    <div class="login-container">
        <div class="logo-wrapper">
            <div class="logo-glow"></div>
            <div class="logo-inner">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L4 5V11C4 16.55 7.42 21.74 12 23C16.58 21.74 20 16.55 20 11V5L12 2Z" fill="url(#sentryShieldGrad)" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>
                    <path d="M12 7V17" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
                    <path d="M9 12H15" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
                    <defs>
                        <linearGradient id="sentryShieldGrad" x1="4" y1="2" x2="20" y2="23" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#10A37F"/>
                            <stop offset="1" stop-color="#005B41"/>
                        </linearGradient>
                    </defs>
                </svg>
            </div>
        </div>
        <div class="login-title">Sentry Agentic</div>
        <div class="login-subtitle">Securing and Automating Threat Operations</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown('<div class="login-form-card">', unsafe_allow_html=True)
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", key="login_user", placeholder="Enter username")
            password = st.text_input("Password", type="password", key="login_pass", placeholder="Enter password")
            submitted = st.form_submit_button("Sign In", use_container_width=True)

        if submitted and username and password:
            is_locked, remaining = check_lockout(username)
            if is_locked:
                st.error(f"🔒 Account locked. Try again in {remaining}s.")
                return

            users = get_users()
            if username not in users:
                locked = record_failed_attempt(username)
                if locked:
                    st.error(f"🔒 Too many attempts. Locked for {LOCKOUT_DURATION_SECONDS}s.")
                else:
                    st.error("❌ Invalid username or password.")
                return

            user_data = users[username]
            if not isinstance(user_data, dict):
                st.error("❌ Invalid user configuration.")
                return

            stored_pw = user_data.get("password_hash") or user_data.get("password", "")
            if not verify_password(password, stored_pw):
                locked = record_failed_attempt(username)
                if locked:
                    st.error(f"🔒 Too many attempts. Locked for {LOCKOUT_DURATION_SECONDS}s.")
                else:
                    st.error("❌ Invalid username or password.")
                return

            # Password verified — proceed
            reset_attempts(username)
            st.session_state.auth_username = username
            st.session_state.user_info = {
                "email": username,
                "name": user_data.get("name", username),
            }

            # Load user's theme
            profile = load_user_profile(username)
            st.session_state.user_theme = profile.get("theme", "Dark")

            # Check 2FA
            totp_secret = user_data.get("totp_secret", "")
            if totp_secret:
                st.session_state.auth_step = "2fa"
            else:
                st.session_state.auth_step = "setup_2fa"
            st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)


# ============================================
# Login Page — Step 2: TOTP 2FA
# ============================================
def render_2fa_page():
    """Render the TOTP 2FA verification screen."""
    st.markdown("""
    <div class="twofa-container">
        <div class="twofa-icon">🔐</div>
        <div class="twofa-title">Two-Factor Authentication</div>
        <div class="twofa-subtitle">Enter the 6-digit code from your authenticator app</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        with st.form("totp_form", clear_on_submit=True):
            code = st.text_input("Code", max_chars=6, key="totp_input", placeholder="000000")
            submitted = st.form_submit_button("Verify", use_container_width=True)

        if submitted and code:
            username = st.session_state.auth_username
            users = get_users()
            totp_secret = users.get(username, {}).get("totp_secret", "")
            if verify_totp(totp_secret, code):
                st.session_state.authenticated = True
                st.session_state.auth_step = "done"
                # Load chats
                chats, active_id = load_chats(username)
                st.session_state.chats = chats
                st.session_state.active_chat_id = active_id
                st.rerun()
            else:
                st.error("❌ Invalid code. Please try again.")

        if st.button("← Back to login", key="back_from_2fa"):
            st.session_state.auth_step = "login"
            st.rerun()


# ============================================
# Login Page — Step 2b: Setup 2FA (QR Code)
# ============================================
def render_setup_2fa_page():
    """Render the 2FA setup page with a QR code to scan."""
    username = st.session_state.auth_username
    users = get_users()
    user_data = users.get(username, {})
    totp_secret = user_data.get("totp_secret", "")

    if not totp_secret:
        totp_secret = pyotp.random_base32()

    st.markdown("""
    <div class="twofa-container">
        <div class="twofa-icon">📱</div>
        <div class="twofa-title">Set Up Two-Factor Authentication</div>
        <div class="twofa-subtitle">Scan the QR code below with Google Authenticator or a similar app</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        qr_b64 = generate_qr_code_base64(username, totp_secret)
        st.markdown(
            f'<div style="text-align:center"><img src="data:image/png;base64,{qr_b64}" width="200"></div>',
            unsafe_allow_html=True
        )
        st.markdown("")

        with st.expander("🔑 Manual entry key"):
            st.code(totp_secret)

        st.markdown("")
        with st.form("setup_2fa_form", clear_on_submit=True):
            code = st.text_input("Enter the 6-digit code to verify setup", max_chars=6, placeholder="000000")
            submitted = st.form_submit_button("Verify & Enable 2FA", use_container_width=True)

        if submitted and code:
            if verify_totp(totp_secret, code):
                st.success("✅ 2FA has been set up successfully!")
                st.info(f"⚠️ **Important**: Ask your administrator to save this TOTP secret to your configuration:\n\n`totp_secret = \"{totp_secret}\"`")
                st.session_state.authenticated = True
                st.session_state.auth_step = "done"
                chats, active_id = load_chats(username)
                st.session_state.chats = chats
                st.session_state.active_chat_id = active_id
                time.sleep(2)
                st.rerun()
            else:
                st.error("❌ Invalid code. Please try again.")

        if st.button("← Back to login", key="back_from_setup"):
            st.session_state.auth_step = "login"
            st.rerun()


# ============================================
# Sidebar — ChatGPT-Style
# ============================================
def _group_chats_by_date(chats: dict) -> dict:
    """Group chats by date labels: Today, Yesterday, Previous 7 Days, Older."""
    now = datetime.now()
    today = now.date()
    yesterday = today - timedelta(days=1)
    week_ago = today - timedelta(days=7)

    groups = {
        "Today": [],
        "Yesterday": [],
        "Previous 7 Days": [],
        "Older": [],
    }

    for chat_id, chat_data in chats.items():
        try:
            created = datetime.fromisoformat(chat_data.get("created_at", "")).date()
        except Exception:
            created = today

        entry = (chat_id, chat_data)
        if created == today:
            groups["Today"].append(entry)
        elif created == yesterday:
            groups["Yesterday"].append(entry)
        elif created >= week_ago:
            groups["Previous 7 Days"].append(entry)
        else:
            groups["Older"].append(entry)

    # Sort each group by created_at descending
    for label in groups:
        groups[label].sort(key=lambda x: x[1].get("created_at", ""), reverse=True)

    return groups


def render_sidebar():
    """Render the ChatGPT-style sidebar with premium Sentry Agentic branding."""
    with st.sidebar:
        # --- Premium Brand Header ---
        st.markdown("""
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:24px; padding:6px 4px; border-bottom:1px solid rgba(255,255,255,0.05);">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L4 5V11C4 16.55 7.42 21.74 12 23C16.58 21.74 20 16.55 20 11V5L12 2Z" fill="#10A37F" stroke="rgba(255,255,255,0.25)" stroke-width="1.5"/>
                <path d="M12 7V17" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
                <path d="M9 12H15" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <span style="font-size:16px; font-weight:700; font-family:'Inter',sans-serif; background:linear-gradient(135deg, #FFFFFF 40%, #A3A3A3 100%); -webkit-background-clip:text; -webkit-text-fill-color:transparent; letter-spacing:-0.3px;">Sentry Agentic</span>
        </div>
        """, unsafe_allow_html=True)

        # New Chat button (accent styled)
        st.markdown('<div class="new-chat-btn">', unsafe_allow_html=True)
        if st.button("✨ New Chat", use_container_width=True, key="new_chat_btn"):
            create_new_chat()
            st.session_state.current_view = "chat"
            _auto_save()
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

        # Search chats
        search_query = st.text_input("🔍 Search chats", key="chat_search", placeholder="Search...", label_visibility="collapsed")

        st.markdown("---")

        # --- Chat history grouped by date ---
        if st.session_state.chats:
            groups = _group_chats_by_date(st.session_state.chats)

            for label, chat_list in groups.items():
                if not chat_list:
                    continue

                # Filter by search
                if search_query:
                    chat_list = [
                        (cid, cd) for cid, cd in chat_list
                        if search_query.lower() in cd.get("title", "").lower()
                    ]
                    if not chat_list:
                        continue

                st.markdown(f'<div class="chat-date-label">{label}</div>', unsafe_allow_html=True)

                for chat_id, chat_data in chat_list:
                    title = chat_data.get("title", "New chat")
                    is_active = chat_id == st.session_state.active_chat_id and st.session_state.current_view == "chat"

                    col_chat, col_del = st.columns([5, 1])
                    with col_chat:
                        css_class = "active-chat" if is_active else ""
                        st.markdown(f'<div class="{css_class}">', unsafe_allow_html=True)
                        if st.button(
                            f"💬 {title}",
                            key=f"chat_{chat_id}",
                            use_container_width=True,
                        ):
                            st.session_state.active_chat_id = chat_id
                            st.session_state.current_view = "chat"
                            st.rerun()
                        st.markdown('</div>', unsafe_allow_html=True)
                    with col_del:
                        if st.button("🗑", key=f"del_{chat_id}"):
                            del st.session_state.chats[chat_id]
                            if st.session_state.active_chat_id == chat_id:
                                st.session_state.active_chat_id = None
                            _auto_save()
                            st.rerun()

        # --- Bottom section ---
        st.markdown("---")

        # Settings button
        if st.button("⚙️ Settings", use_container_width=True, key="settings_btn"):
            st.session_state.current_view = "settings"
            st.rerun()

        # Profile section
        user = st.session_state.user_info or {}
        user_name = user.get("name", "User")
        username = user.get("email", "")
        avatar_path = get_avatar_path(username) if username else None

        if avatar_path:
            st.markdown(f"""
            <div class="profile-section">
                <img src="data:image/png;base64,{_img_to_base64(avatar_path)}" class="profile-avatar">
                <span style="color: #ECECEC; font-weight: 500;">{user_name}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"👤 **{user_name}**")

        if st.button("🚪 Sign Out", use_container_width=True, key="signout_btn"):
            _auto_save()
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()


def _img_to_base64(image_path: str) -> str:
    """Convert an image file to base64 string."""
    try:
        with open(image_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    except Exception:
        return ""


# ============================================
# Settings Page
# ============================================
def render_settings():
    """Render the settings page."""
    st.markdown("## ⚙️ Settings")
    st.markdown("")

    user = st.session_state.user_info or {}
    username = user.get("email", "")
    user_name = user.get("name", "User")
    profile = load_user_profile(username) if username else {}

    tab1, tab2, tab3, tab4 = st.tabs(["👤 Profile", "🔒 Security", "🎨 Appearance", "🤖 Model"])

    # --- Profile Tab ---
    with tab1:
        st.markdown('<div class="settings-card">', unsafe_allow_html=True)

        avatar_path = get_avatar_path(username)

        # Avatar with + overlay (HTML only, decorative)
        if avatar_path:
            avatar_html = f'<img src="data:image/png;base64,{_img_to_base64(avatar_path)}">'
        else:
            avatar_html = '<div class="avatar-placeholder" style="background:#444;display:flex;align-items:center;justify-content:center;font-size:36px;">👤</div>'

        st.markdown(f'''
        <div class="avatar-container">
            {avatar_html}
        </div>
        ''', unsafe_allow_html=True)

        # Clickable + button that opens file picker
        with st.popover("＋", use_container_width=False):
            uploaded = st.file_uploader(
                "Pick a photo",
                type=["png", "jpg", "jpeg", "webp"],
                key="avatar_upload",
                label_visibility="collapsed",
            )
            if uploaded:
                save_avatar(username, uploaded)
                st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

        # Display name (read-only)
        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Account Info</div>', unsafe_allow_html=True)
        st.text_input("Display Name", value=user_name, disabled=True, key="settings_display_name")
        st.text_input("Username", value=username, disabled=True, key="settings_username")
        st.markdown('</div>', unsafe_allow_html=True)

    # --- Security Tab ---
    with tab2:
        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Change Password</div>', unsafe_allow_html=True)

        with st.form("change_password_form", clear_on_submit=True):
            current_pw = st.text_input("Current Password", type="password", key="cur_pw")
            new_pw = st.text_input("New Password", type="password", key="new_pw")
            confirm_pw = st.text_input("Confirm New Password", type="password", key="conf_pw")
            change_submitted = st.form_submit_button("Update Password", use_container_width=True)

        if change_submitted:
            if not current_pw or not new_pw or not confirm_pw:
                st.error("❌ All fields are required.")
            elif new_pw != confirm_pw:
                st.error("❌ New passwords do not match.")
            elif len(new_pw) < 6:
                st.error("❌ Password must be at least 6 characters.")
            else:
                users = get_users()
                user_data = users.get(username, {})
                stored_pw = user_data.get("password_hash") or user_data.get("password", "")
                if not verify_password(current_pw, stored_pw):
                    st.error("❌ Current password is incorrect.")
                else:
                    save_password_override(username, hash_password(new_pw))
                    st.success("✅ Password updated successfully!")

        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Two-Factor Authentication</div>', unsafe_allow_html=True)

        # Check if user has TOTP set up
        users = get_users()
        user_data = users.get(username, {})
        totp_enabled = bool(user_data.get("totp_secret"))

        col_2fa_status, col_2fa_toggle = st.columns([4, 2])
        with col_2fa_status:
            if totp_enabled:
                st.markdown(
                    '<div style="display:flex;align-items:center;gap:8px;padding:8px 0;">'
                    '<div style="width:10px;height:10px;border-radius:50%;background:#4CAF50;"></div>'
                    '<span style="font-size:14px;">Enabled</span></div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div style="display:flex;align-items:center;gap:8px;padding:8px 0;">'
                    '<div style="width:10px;height:10px;border-radius:50%;background:#666;"></div>'
                    '<span style="font-size:14px;">Disabled</span></div>',
                    unsafe_allow_html=True
                )
        with col_2fa_toggle:
            toggle_val = st.toggle("Enable 2FA", value=totp_enabled, key="toggle_2fa", label_visibility="collapsed")
            if toggle_val != totp_enabled:
                if toggle_val:
                    st.info("📱 Contact your administrator to set up 2FA.")
                else:
                    st.warning("⚠️ Disabling 2FA requires administrator approval.")

        st.markdown('</div>', unsafe_allow_html=True)

    # --- Appearance Tab ---
    with tab3:
        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Color Theme</div>', unsafe_allow_html=True)

        current_theme = st.session_state.get("user_theme", "Dark")
        theme_names = list(THEME_PRESETS.keys())

        # Show theme previews
        cols = st.columns(len(theme_names))
        for i, name in enumerate(theme_names):
            t = THEME_PRESETS[name]
            with cols[i]:
                selected = name == current_theme
                border_style = f"3px solid {t['accent']}" if selected else f"1px solid {t['border']}"
                st.markdown(f"""
                <div style="background:{t['bg_primary']};border:{border_style};border-radius:12px;padding:16px;text-align:center;margin-bottom:8px;">
                    <div style="width:32px;height:32px;border-radius:50%;background:{t['accent']};margin:0 auto 8px auto;"></div>
                    <div style="color:{t['text_primary']};font-size:12px;font-weight:600;">{name}</div>
                </div>
                """, unsafe_allow_html=True)

        selected_theme = st.selectbox(
            "Select Theme",
            theme_names,
            index=theme_names.index(current_theme),
            key="theme_selector"
        )

        if selected_theme != current_theme:
            st.session_state.user_theme = selected_theme
            profile["theme"] = selected_theme
            save_user_profile(username, profile)
            st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

    # --- Model Tab ---
    with tab4:
        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Active Provider</div>', unsafe_allow_html=True)

        current_provider = st.session_state.get("provider", "Not set")
        st.markdown(f"**Current:** `{current_provider}`")

        if current_provider == "openrouter":
            st.success("🆓 Using free OpenRouter models — no cost!")
        elif current_provider:
            st.info(f"💳 Using **{current_provider}** (API key from secrets)")

        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="settings-card">', unsafe_allow_html=True)
        st.markdown('<div class="settings-title">Free Models (via OpenRouter)</div>', unsafe_allow_html=True)

        if AGENT_AVAILABLE:
            st.markdown("Select from high-performing free models. These require an [OpenRouter API key](https://openrouter.ai/keys) in your secrets (`openrouter_api_key`).")
            st.markdown("")

            current_model = st.session_state.get("selected_model_id")
            model_options = [f"{m['name']}  {'🟢' if m['tier'] == 'high' else '🟡'}" for m in OPENROUTER_FREE_MODELS]
            model_ids = [m["id"] for m in OPENROUTER_FREE_MODELS]

            try:
                current_idx = model_ids.index(current_model) if current_model in model_ids else 0
            except ValueError:
                current_idx = 0

            selected_idx = st.selectbox(
                "Select Model",
                range(len(model_options)),
                format_func=lambda i: model_options[i],
                index=current_idx,
                key="model_selector"
            )

            if model_ids[selected_idx] != current_model:
                st.session_state.selected_model_id = model_ids[selected_idx]

            # Show model details
            selected_model = OPENROUTER_FREE_MODELS[selected_idx]
            st.markdown(f"**Model ID:** `{selected_model['id']}`")
            tier_label = "🟢 High performance" if selected_model["tier"] == "high" else "🟡 Medium performance"
            st.markdown(f"**Tier:** {tier_label}")

            # Switch to OpenRouter button
            if current_provider != "openrouter":
                general = dict(st.secrets.get("general", {}))
                if general.get("openrouter_api_key"):
                    if st.button("🔄 Switch to OpenRouter (Free)", use_container_width=True, key="switch_openrouter"):
                        st.session_state.provider = "openrouter"
                        st.session_state.api_key = general["openrouter_api_key"]
                        st.rerun()
                else:
                    st.warning("⚠️ Add `openrouter_api_key` to your Streamlit secrets to use free models.")
        else:
            st.error("Agent modules not available.")

        st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("")
    if st.button("← Back to Chat", key="back_to_chat_btn", use_container_width=False):
        st.session_state.current_view = "chat"
        st.rerun()


# ============================================
# Main Chat Area
# ============================================
def render_chat():
    """Render the main chat interface."""
    # Check agent availability first
    if not AGENT_AVAILABLE:
        st.error(f"❌ Agent modules failed to load: {_IMPORT_ERROR}")
        return

    # Initialize LLM provider
    if st.session_state.provider is None:
        try:
            provider, api_key = get_available_provider(dict(st.secrets))
            if provider:
                st.session_state.provider = provider
                st.session_state.api_key = api_key
            else:
                st.error(f"❌ {api_key}")
                return
        except Exception as e:
            st.error(f"❌ LLM provider error: {e}")
            return

    # Initialize sites data
    if st.session_state.sites_data is None:
        with st.spinner("Loading sites..."):
            st.session_state.sites_data = fetch_sites()

    chat = get_active_chat()
    messages = chat["messages"]

    # Get user avatar for chat display
    username = (st.session_state.user_info or {}).get("email", "")
    avatar_path = get_avatar_path(username) if username else None
    user_avatar = avatar_path if avatar_path else "👤"

    # --- Header with nav and Share button ---
    col_prev, col_next, col_spacer, col_share = st.columns([0.5, 0.5, 8, 1])

    # Get sorted chat IDs for navigation
    chat_ids = list(st.session_state.chats.keys())
    current_id = st.session_state.active_chat_id
    current_idx = chat_ids.index(current_id) if current_id in chat_ids else 0

    with col_prev:
        if st.button("◀", key="nav_prev", help="Previous chat"):
            if len(chat_ids) > 1:
                prev_idx = (current_idx - 1) % len(chat_ids)
                st.session_state.active_chat_id = chat_ids[prev_idx]
                st.rerun()
    with col_next:
        if st.button("▶", key="nav_next", help="Next chat"):
            if len(chat_ids) > 1:
                next_idx = (current_idx + 1) % len(chat_ids)
                st.session_state.active_chat_id = chat_ids[next_idx]
                st.rerun()
    with col_share:
        if messages:
            if st.button("📤 Share", key="share_btn"):
                _share_chat(chat)

    # Welcome screen (no messages yet)
    if not messages:
        st.markdown("""
        <div class="main-header">
            <div class="logo-wrapper">
                <div class="logo-glow"></div>
                <div class="logo-inner">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L4 5V11C4 16.55 7.42 21.74 12 23C16.58 21.74 20 16.55 20 11V5L12 2Z" fill="#10A37F" stroke="rgba(255,255,255,0.2)" stroke-width="1.5"/>
                        <path d="M12 7V17" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
                        <path d="M9 12H15" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </div>
            </div>
            <h1>Sentry Agentic</h1>
            <p>Autonomous Co-pilot for Cybersecurity and Threat Operations</p>
        </div>
        """, unsafe_allow_html=True)

        # Suggestion chips
        st.markdown("")
        cols = st.columns(3)
        suggestions = [
            "What sites are available?",
            "Show threats on Etranzact this month",
            "Check agent health across all sites",
        ]
        for i, suggestion in enumerate(suggestions):
            with cols[i]:
                if st.button(suggestion, key=f"suggest_{i}", use_container_width=True):
                    chat["messages"].append({"role": "user", "content": suggestion})
                    chat["title"] = generate_chat_title(suggestion)
                    _process_and_respond(suggestion)
                    st.rerun()
    else:
        # Render chat messages
        for msg in messages:
            if msg["role"] == "user":
                with st.chat_message("user", avatar=user_avatar):
                    st.markdown(msg["content"])
                    # Display inline image if present
                    if msg.get("image_path") and os.path.exists(msg["image_path"]):
                        st.image(msg["image_path"], width=300)
            else:
                with st.chat_message("assistant", avatar="🛡️"):
                    st.markdown(msg["content"])

    # Chat input first (Streamlit pins this to bottom with built-in ➤ send arrow)
    if prompt := st.chat_input("Ask anything...", key="agent_input"):
        pass  # handled below

    # --- Sub-toolbar: + (attach) | Model selector  — sits below the input ---
    sub1, sub2, sub3 = st.columns([0.4, 2.5, 9.1])
    with sub1:
        with st.popover("＋", use_container_width=True):
            uploaded_img = st.file_uploader(
                "Attach",
                type=["png", "jpg", "jpeg", "webp", "gif"],
                key="chat_image_upload",
                label_visibility="collapsed",
            )
            if uploaded_img:
                st.session_state.pending_image = uploaded_img
                st.success("✓")
    with sub2:
        if AGENT_AVAILABLE:
            provider = st.session_state.get("provider", "groq")
            model_labels = [m["name"] for m in OPENROUTER_FREE_MODELS]
            all_labels = [f"{provider} (default)"] + model_labels
            all_ids = [None] + [m["id"] for m in OPENROUTER_FREE_MODELS]

            current_model = st.session_state.get("selected_model_id")
            try:
                cur_idx = all_ids.index(current_model) if current_model in all_ids else 0
            except ValueError:
                cur_idx = 0

            sel = st.selectbox(
                "Model",
                range(len(all_labels)),
                format_func=lambda i: all_labels[i],
                index=cur_idx,
                key="chat_model_sel",
                label_visibility="collapsed",
            )
            if all_ids[sel] != current_model:
                st.session_state.selected_model_id = all_ids[sel]
                if all_ids[sel] is not None and provider != "openrouter":
                    general = dict(st.secrets.get("general", {}))
                    if general.get("openrouter_api_key"):
                        st.session_state.provider = "openrouter"
                        st.session_state.api_key = general["openrouter_api_key"]

    # Show pending image preview
    if st.session_state.get("pending_image"):
        st.image(st.session_state.pending_image, width=100)

    # Process the prompt if submitted
    if prompt:
        # Handle attached image
        image_path = None
        image_data = None
        if st.session_state.get("pending_image"):
            image_file = st.session_state.pending_image
            image_path = save_chat_image(username, image_file)
            # Read image bytes for LLM
            image_file.seek(0)
            image_data = image_file.read()
            st.session_state.pending_image = None

        msg_data = {"role": "user", "content": prompt}
        if image_path:
            msg_data["image_path"] = image_path
        chat["messages"].append(msg_data)

        if len(chat["messages"]) == 1:
            chat["title"] = generate_chat_title(prompt)

        with st.chat_message("user", avatar=user_avatar):
            st.markdown(prompt)
            if image_path:
                st.image(image_path, width=300)

        with st.chat_message("assistant", avatar="🛡️"):
            _process_and_respond(prompt, image_data=image_data)

        st.rerun()


def _share_chat(chat: dict):
    """Generate a sharable summary of the chat."""
    lines = []
    lines.append(f"# {chat.get('title', 'Chat')}")
    lines.append(f"*Shared from Sentry Agentic — {datetime.now().strftime('%Y-%m-%d %H:%M')}*")
    lines.append("")
    for msg in chat.get("messages", []):
        role = "**You**" if msg["role"] == "user" else "**Agent**"
        lines.append(f"{role}: {msg['content']}")
        lines.append("")

    share_text = "\n".join(lines)

    st.download_button(
        label="📄 Download Chat",
        data=share_text,
        file_name=f"chat_{datetime.now().strftime('%Y%m%d_%H%M')}.md",
        mime="text/markdown",
        key="download_share"
    )


def _process_and_respond(user_query: str, stream_display: bool = False, image_data: bytes = None):
    """Process the user query through the agent and add the response."""
    chat = get_active_chat()

    if not AGENT_AVAILABLE:
        response = "❌ Agent modules not available. Check agent_llm.py and agent_tools.py."
        chat["messages"].append({"role": "assistant", "content": response})
        return

    with st.spinner("🔍 Investigating..."):
        kwargs = {
            "user_query": user_query,
            "chat_history": chat["messages"],
            "sites_data": st.session_state.sites_data,
            "api_key": st.session_state.api_key,
            "current_date": datetime.now().strftime("%Y-%m-%d"),
            "provider": st.session_state.provider,
        }
        # Pass image data if available
        if image_data:
            kwargs["image_data"] = image_data
        # Pass OpenRouter model selection
        if st.session_state.get("selected_model_id"):
            kwargs["model_id"] = st.session_state.selected_model_id

        result = process_user_query(**kwargs)

    # Clean response — no tool labels
    response = result.get("response", "Sorry, I couldn't process that query.")

    chat["messages"].append({"role": "assistant", "content": response})
    _auto_save()


# ============================================
# Auto-save helper
# ============================================
def _auto_save():
    """Save chats for the current user."""
    user_info = st.session_state.get("user_info")
    if user_info:
        username = user_info.get("email", "")
        if username:
            save_chats(
                username,
                st.session_state.chats,
                st.session_state.active_chat_id
            )


# ============================================
# Main Entry Point
# ============================================
def main():
    init_session_state()
    theme = st.session_state.get("user_theme", "Dark")
    st.markdown(_build_css(theme), unsafe_allow_html=True)

    # Auth flow: login → setup_2fa / 2fa → chat
    if not st.session_state.authenticated:
        if st.session_state.auth_step == "setup_2fa":
            render_setup_2fa_page()
        elif st.session_state.auth_step == "2fa":
            render_2fa_page()
        else:
            render_login_page()
        return

    # Authenticated — show sidebar + content
    render_sidebar()

    if st.session_state.current_view == "settings":
        render_settings()
    else:
        render_chat()


if __name__ == "__main__":
    main()
