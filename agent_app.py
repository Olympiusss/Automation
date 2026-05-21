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
    page_title="SentinelOne AI Agent",
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
    """Build CSS from a theme preset."""
    t = THEME_PRESETS.get(theme_name, THEME_PRESETS["Dark"])
    return f"""
<style>
/* --- Global --- */
.stApp {{
    background-color: {t["bg_primary"]} !important;
    color: {t["text_primary"]} !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
    font-weight: 400 !important;
}}
header[data-testid="stHeader"] {{
    background-color: {t["bg_primary"]} !important;
}}
div[data-testid="stToolbar"] {{
    display: none !important;
}}

/* --- Sidebar --- */
section[data-testid="stSidebar"] {{
    background-color: {t["bg_secondary"]} !important;
    border-right: 1px solid {t["border"]} !important;
}}
section[data-testid="stSidebar"] .stMarkdown,
section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] label {{
    color: {t["text_primary"]} !important;
}}

/* --- Buttons --- */
.stButton > button {{
    background-color: transparent !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 10px !important;
    transition: all 0.2s ease !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
    font-weight: 400 !important;
    font-size: 13px !important;
}}
.stButton > button:hover {{
    background-color: {t["sidebar_active"]} !important;
    border-color: {t["accent"]} !important;
}}

/* New Chat button accent */
.new-chat-btn > button {{
    background-color: {t["accent"]} !important;
    color: #FFF !important;
    border: none !important;
    font-weight: 400 !important;
}}
.new-chat-btn > button:hover {{
    background-color: {t["accent_hover"]} !important;
}}

/* Active chat highlight */
.active-chat > button {{
    background-color: {t["sidebar_active"]} !important;
    border-color: {t["accent"]} !important;
}}

/* --- Chat messages --- */
div[data-testid="stChatMessage"] {{
    border-radius: 16px !important;
    padding: 12px 16px !important;
    margin-bottom: 8px !important;
    max-width: 85% !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
    font-size: 14px !important;
    font-weight: 400 !important;
    line-height: 1.6 !important;
}}

/* --- Chat Input --- */
div[data-testid="stChatInput"] {{
    background-color: {t["bg_input"]} !important;
    border-radius: 24px !important;
    border: 1px solid {t["border"]} !important;
    max-width: 800px !important;
    margin: 0 auto !important;
}}
div[data-testid="stChatInput"] textarea {{
    color: {t["text_primary"]} !important;
    background-color: transparent !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
    font-size: 14px !important;
}}

/* --- Scrollbar --- */
::-webkit-scrollbar {{ width: 6px; }}
::-webkit-scrollbar-track {{ background: transparent; }}
::-webkit-scrollbar-thumb {{ background: {t["border"]}; border-radius: 3px; }}

/* --- Login Page --- */
.login-container {{
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; min-height: 70vh; text-align: center;
}}
.login-logo {{ font-size: 64px; margin-bottom: 16px; }}
.login-title {{
    color: {t["text_primary"]}; font-size: 24px; font-weight: 400; margin-bottom: 4px;
    font-family: 'Times New Roman', Times, Georgia, serif;
}}
.login-subtitle {{
    color: {t["text_secondary"]}; font-size: 13px; margin-bottom: 32px;
    font-family: 'Times New Roman', Times, Georgia, serif;
}}
.login-form input {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 10px !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
}}
.login-form label {{
    color: {t["text_secondary"]} !important;
}}

/* --- 2FA --- */
.twofa-container {{
    display: flex; flex-direction: column; align-items: center;
    justify-content: center; min-height: 60vh; text-align: center;
}}
.twofa-icon {{ font-size: 48px; margin-bottom: 12px; }}
.twofa-title {{
    color: {t["text_primary"]}; font-size: 22px; font-weight: 600; margin-bottom: 4px;
}}
.twofa-subtitle {{
    color: {t["text_secondary"]}; font-size: 14px; margin-bottom: 24px;
}}

/* --- Welcome Screen --- */
.main-header {{
    text-align: center; padding-top: 15vh;
}}
.main-header h1 {{
    color: {t["text_primary"]} !important;
    font-size: 24px !important; font-weight: 400 !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
}}

/* --- Settings page --- */
.settings-card {{
    background-color: {t["bg_tertiary"]};
    border: 1px solid {t["border"]};
    border-radius: 16px;
    padding: 24px;
    margin-bottom: 16px;
}}
.settings-title {{
    color: {t["text_primary"]}; font-size: 16px; font-weight: 400;
    margin-bottom: 12px; font-family: 'Times New Roman', Times, Georgia, serif;
}}

/* --- Profile avatar --- */
.profile-section {{
    display: flex; align-items: center; gap: 12px; padding: 8px 0;
}}
.profile-avatar {{
    width: 36px; height: 36px; border-radius: 50%;
    object-fit: cover; border: 2px solid {t["accent"]};
}}
.profile-avatar-large {{
    width: 80px; height: 80px; border-radius: 50%;
    object-fit: cover; border: 3px solid {t["accent"]};
}}

/* --- Chat date groups --- */
.chat-date-label {{
    color: {t["text_secondary"]}; font-size: 11px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px;
    padding: 8px 8px 4px 8px; margin-top: 8px;
    font-family: 'Inter', sans-serif;
}}

/* --- Tabs in settings --- */
.stTabs [data-baseweb="tab-list"] {{
    background-color: transparent !important;
    gap: 4px !important;
}}
.stTabs [data-baseweb="tab"] {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_secondary"]} !important;
    border-radius: 8px !important;
    border: 1px solid {t["border"]} !important;
    font-family: 'Inter', sans-serif !important;
}}
.stTabs [aria-selected="true"] {{
    background-color: {t["accent"]} !important;
    color: #FFF !important;
    border-color: {t["accent"]} !important;
}}

/* File uploader */
div[data-testid="stFileUploader"] {{
    background-color: {t["bg_tertiary"]} !important;
    border: 1px dashed {t["border"]} !important;
    border-radius: 12px !important;
}}
div[data-testid="stFileUploader"] label {{
    color: {t["text_primary"]} !important;
}}

/* Expander */
.streamlit-expanderHeader {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border-radius: 8px !important;
}}

/* Text inputs in settings */
.stTextInput input {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
    border-radius: 10px !important;
}}
.stTextInput label {{
    color: {t["text_secondary"]} !important;
}}

/* Select boxes */
.stSelectbox > div > div {{
    background-color: {t["bg_tertiary"]} !important;
    color: {t["text_primary"]} !important;
    border: 1px solid {t["border"]} !important;
}}

/* --- Share toast --- */
.share-toast {{
    position: fixed; bottom: 80px; left: 50%; transform: translateX(-50%);
    background: {t["accent"]}; color: #FFF; padding: 10px 24px;
    border-radius: 10px; font-size: 14px; z-index: 9999;
    animation: fadeOut 2s ease forwards;
}}
@keyframes fadeOut {{
    0% {{ opacity:1; }} 70% {{ opacity:1; }} 100% {{ opacity:0; }}
}}

/* --- Settings tab spacing --- */
div[data-testid="stTabs"] > div[role="tablist"] {{
    gap: 32px !important;
    justify-content: center !important;
    padding: 4px 0 12px 0 !important;
}}
div[data-testid="stTabs"] > div[role="tablist"] button {{
    padding: 12px 32px !important;
    font-size: 13px !important;
    font-family: 'Times New Roman', Times, Georgia, serif !important;
    font-weight: 400 !important;
    letter-spacing: 0.5px !important;
}}
div[data-testid="stTabs"] > div[role="tablist"] button[aria-selected="true"] {{
    font-weight: 400 !important;
}}

/* --- Chat sub-toolbar (+ and model) --- */
.chat-subtoolbar {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 6px 16px;
    max-width: 800px;
    margin: 0 auto;
}}
.chat-subtoolbar .attach-btn {{
    background: none;
    border: none;
    color: {t["text_secondary"]};
    font-size: 18px;
    cursor: pointer;
    padding: 2px 6px;
    border-radius: 6px;
}}
.chat-subtoolbar .attach-btn:hover {{
    background: {t["sidebar_active"]};
}}

/* --- Avatar + overlay --- */
.avatar-container {{
    position: relative;
    display: inline-block;
    width: 80px;
    height: 80px;
}}
.avatar-container img, .avatar-container .avatar-placeholder {{
    width: 80px;
    height: 80px;
    border-radius: 50%;
    object-fit: cover;
}}
.avatar-plus {{
    position: absolute;
    bottom: 0;
    right: 0;
    width: 26px;
    height: 26px;
    border-radius: 50%;
    background: {t["accent"]};
    color: #FFF;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    font-weight: 400;
    border: 2px solid {t["bg_primary"]};
    cursor: pointer;
}}

/* --- Hide avatar file uploader completely --- */
.avatar-file-hidden {{
    max-height: 0;
    overflow: hidden;
    opacity: 0;
    margin: 0 !important;
    padding: 0 !important;
}}

/* --- Hide file uploader labels --- */
div[data-testid="stFileUploader"] section {{
    padding: 0 !important;
}}
div[data-testid="stFileUploader"] section > div {{
    display: none !important;
}}
div[data-testid="stFileUploader"] section > button {{
    display: none !important;
}}
div[data-testid="stFileUploader"] small {{
    display: none !important;
}}
div[data-testid="stFileUploader"] label {{
    display: none !important;
}}
/* Make uploader invisible — we show our own + button */
div[data-testid="stFileUploader"] {{
    max-width: 40px !important;
    overflow: hidden !important;
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
    """Render the username/password login screen."""
    st.markdown("""
    <div class="login-container">
        <div class="login-logo">🛡️</div>
        <div class="login-title">SentinelOne AI Agent</div>
        <div class="login-subtitle">Sign in to continue</div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown('<div class="login-form">', unsafe_allow_html=True)
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
    """Render the ChatGPT-style sidebar."""
    with st.sidebar:
        # --- Header ---
        st.markdown("#### 🛡️ SentinelOne Agent")

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
            <h1>How can I help you today?</h1>
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
    lines.append(f"*Shared from SentinelOne AI Agent — {datetime.now().strftime('%Y-%m-%d %H:%M')}*")
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
