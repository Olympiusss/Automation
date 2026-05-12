"""
Sentrium Integrated SOC Dashboard — Configuration
All settings loaded from environment variables.
"""

from __future__ import annotations
import os
import json
import logging
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("soc_dashboard.config")


def _parse_json_creds(env_key: str, default: str = "{}") -> dict:
    """Safely parse a JSON dict from an env var.
    Strips outer quotes Railway sometimes adds: '"{}"' -> '{}'
    """
    raw = os.getenv(env_key, default).strip()
    # Strip surrounding single or double quotes Railway may add
    if (raw.startswith('"') and raw.endswith('"')) or \
       (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1]
    try:
        result = json.loads(raw)
        if not isinstance(result, dict):
            logger.error(f"{env_key}: expected JSON object, got {type(result).__name__}")
            return {}
        return result
    except json.JSONDecodeError as e:
        logger.error(f"{env_key}: JSON parse failed — {e} | raw value: {raw!r}")
        return {}

class Settings:
    """Application settings — sourced from environment variables."""

    @property
    def S1_BASE_URL(self) -> str:
        return os.getenv("S1_BASE_URL", "https://euce1-exclusive.sentinelone.net/web/api/v2.1")

    @property
    def S1_API_TOKEN(self) -> str:
        return os.getenv("S1_API_TOKEN", "").strip().strip('"').strip("'")

    @property
    def AV_SUBDOMAIN(self) -> str:
        val = os.getenv("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud")
        val = val.strip().strip('"').strip("'").replace("https://", "").replace("http://", "").rstrip("/")
        return val

    @property
    def AV_CLIENT_ID(self) -> str:
        return os.getenv("AV_CLIENT_ID", "").strip().strip('"').strip("'")

    @property
    def AV_CLIENT_SECRET(self) -> str:
        return os.getenv("AV_CLIENT_SECRET", "").strip().strip('"').strip("'")

    @property
    def TOTP_SECRET(self) -> str:
        return os.getenv("TOTP_SECRET", "").strip().strip('"').strip("'")

    TOTP_APP_NAME: str = "Sentrium SOC Dashboard"
    TOTP_ISSUER: str = "Sentrium Security"

    @property
    def SESSION_TIMEOUT_MINUTES(self) -> int:
        return int(os.getenv("SESSION_TIMEOUT_MINUTES", "480"))

    @property
    def REFRESH_INTERVAL(self) -> int:
        return int(os.getenv("REFRESH_INTERVAL", "30"))

    @property
    def HOST(self) -> str:
        return os.getenv("HOST", "0.0.0.0")

    @property
    def PORT(self) -> int:
        return int(os.getenv("PORT", "8080"))

    @property
    def SECRET_KEY(self) -> str:
        return os.getenv("SECRET_KEY", "sentrium-soc-dashboard-secret-key-change-me")

    @property
    def CLIENT_CREDENTIALS(self) -> dict[str, str]:
        """JSON: {"username":"password"}. One entry per client."""
        return _parse_json_creds("CLIENT_CREDENTIALS")

    @property
    def CLIENT_NAME_MAP(self) -> dict[str, str]:
        """JSON: {"username":"Exact Display Name in S1/AV"}."""
        return _parse_json_creds("CLIENT_NAME_MAP")

    @property
    def ANALYST_CREDENTIALS(self) -> dict[str, str]:
        """JSON: {"username":"password"}. One entry per analyst."""
        return _parse_json_creds("ANALYST_CREDENTIALS")

    @property
    def ADMIN_USERNAME(self) -> str:
        return os.getenv("ADMIN_USERNAME", "admin")

    @property
    def ADMIN_PASSWORD(self) -> str:
        return os.getenv("ADMIN_PASSWORD", "")

    def s1_configured(self) -> bool:
        return bool(self.S1_API_TOKEN)

    def av_configured(self) -> bool:
        return bool(self.AV_CLIENT_ID and self.AV_CLIENT_SECRET)

    def totp_configured(self) -> bool:
        return bool(self.TOTP_SECRET)


settings = Settings()
