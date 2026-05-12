"""
Sentrium Integrated SOC Dashboard — Configuration
All settings loaded from environment variables.
"""

from __future__ import annotations
import os
import json
from dotenv import load_dotenv

load_dotenv()

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
        """JSON object mapping client usernames to passwords.
        Example: {"xpresspayment":"pass1","zone-payment":"pass2"}
        """
        raw = os.getenv("CLIENT_CREDENTIALS", "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    @property
    def CLIENT_NAME_MAP(self) -> dict[str, str]:
        """Optional JSON mapping: login username -> exact client display name in S1/AV.
        Use this when the username differs from the real client name (spaces, casing, etc).
        Example: {"zone-payment":"Zone Payment Network Limited","xpress":"Xpresspayment"}
        If a username is NOT in this map, the username itself is used as the client name.
        """
        raw = os.getenv("CLIENT_NAME_MAP", "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    @property
    def ANALYST_CREDENTIALS(self) -> dict[str, str]:
        """JSON object mapping analyst usernames to passwords.
        Example: {"soc-analyst":"secret1"}
        """
        raw = os.getenv("ANALYST_CREDENTIALS", "{}")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

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
