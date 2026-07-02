"""
Sentrium Integrated SOC Dashboard — Configuration
All settings loaded from environment variables.

Variable naming: Railway uses SOC_* prefixed names for SOC-specific credentials
to avoid conflicts with the main Flask app. We check SOC_* first, then fall
back to the unprefixed name so both naming conventions work.
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
        # SOC dashboard uses SOC_S1_BASE_URL exclusively.
        # The main Flask S1 apps use S1_BASE_URL (unprefixed) — kept separate.
        return os.getenv(
            "SOC_S1_BASE_URL",
            os.getenv("S1_BASE_URL", "https://euce1-exclusive.sentinelone.net/web/api/v2.1")
        )

    @property
    def S1_API_TOKEN(self) -> str:
        # SOC dashboard uses SOC_S1_API_TOKEN exclusively
        # (unprefixed S1_API_TOKEN belongs to the main Flask apps)
        val = os.getenv("SOC_S1_API_TOKEN", "")
        return val.strip().strip('"').strip("'")

    @property
    def AV_SUBDOMAIN(self) -> str:
        # SOC dashboard uses SOC_AV_SUBDOMAIN exclusively.
        # The main Flask AlienVault app uses AV_SUBDOMAIN (unprefixed) — kept separate.
        val = os.getenv("SOC_AV_SUBDOMAIN", os.getenv("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud"))
        val = val.strip().strip('"').strip("'").replace("https://", "").replace("http://", "").rstrip("/")
        return val

    @property
    def AV_CLIENT_ID(self) -> str:
        # SOC dashboard uses SOC_AV_CLIENT_ID exclusively
        # (unprefixed AV_CLIENT_ID belongs to the main AlienVault Flask app)
        val = os.getenv("SOC_AV_CLIENT_ID", "")
        return val.strip().strip('"').strip("'")

    @property
    def AV_CLIENT_SECRET(self) -> str:
        # SOC dashboard uses SOC_AV_CLIENT_SECRET exclusively
        val = os.getenv("SOC_AV_CLIENT_SECRET", "")
        return val.strip().strip('"').strip("'")

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
        # SOC dashboard uses SOC_SECRET_KEY exclusively
        return os.getenv("SOC_SECRET_KEY", "sentrium-soc-dashboard-secret-key-change-me")

    @property
    def CLIENT_CREDENTIALS(self) -> dict[str, str]:
        """JSON: {"username":"password"}. One entry per client."""
        return _parse_json_creds("CLIENT_CREDENTIALS")

    @property
    def CLIENT_NAME_MAP(self) -> dict[str, str]:
        """Map login username → exact S1 site name / AV deployment name.

        A single entry covers BOTH platforms — the fetcher fuzzy-matches this
        name against SentinelOne sites AND AlienVault deployments, then merges
        the data into one unified client card.

        Example:
            {"techcorp": "TechCorp Solutions", "acme": "ACME Corp"}
        """
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

    def log_startup_summary(self) -> None:
        """Log a clear summary of resolved credentials at startup."""
        logger.info("─── SOC Config resolved ───────────────────────────────")
        logger.info(f"  S1 base URL     : {self.S1_BASE_URL}")
        logger.info(f"  S1 token        : {'✓ set' if self.S1_API_TOKEN else '✗ MISSING — S1 data unavailable'}")
        logger.info(f"  AV subdomain    : {self.AV_SUBDOMAIN}")
        logger.info(f"  AV client ID    : {'✓ set' if self.AV_CLIENT_ID else '✗ MISSING — AV data unavailable'}")
        logger.info(f"  AV client secret: {'✓ set' if self.AV_CLIENT_SECRET else '✗ MISSING'}")
        logger.info(f"  Admin username  : {self.ADMIN_USERNAME}")
        logger.info(f"  Clients         : {list(self.CLIENT_CREDENTIALS.keys()) or '(none)'}")
        logger.info(f"  Client name map : {dict(self.CLIENT_NAME_MAP) or '(empty — clients will use login username)'}")
        logger.info(f"  Analysts        : {list(self.ANALYST_CREDENTIALS.keys()) or '(none)'}")
        logger.info(f"  Refresh interval: {self.REFRESH_INTERVAL}s")
        logger.info("────────────────────────────────────────────────────────")

    # ── External Solution SSO ───────────────────────────────────────────

    @property
    def EXTERNAL_SSO_URL(self) -> str:
        return os.getenv("EXTERNAL_SSO_URL", "").strip().rstrip("/")

    @property
    def EXTERNAL_SSO_SECRET(self) -> str:
        return os.getenv("EXTERNAL_SSO_SECRET", "").strip()

    @property
    def EXTERNAL_SSO_ISSUER(self) -> str:
        return os.getenv("EXTERNAL_SSO_ISSUER", "esentry-central")

    @property
    def EXTERNAL_SSO_AUDIENCE(self) -> str:
        return os.getenv("EXTERNAL_SSO_AUDIENCE", "soc-dashboard")

    @property
    def EXTERNAL_SSO_TOKEN_FIELD(self) -> str:
        return os.getenv("EXTERNAL_SSO_TOKEN_FIELD", "token")

    @property
    def EXTERNAL_SSO_TOKEN_TTL(self) -> int:
        return min(int(os.getenv("EXTERNAL_SSO_TOKEN_TTL", "60")), 300)

    @property
    def ANALYST_PROFILES(self) -> dict:
        """JSON: {username: {sub, email, name}} — identity sent in SSO JWT."""
        return _parse_json_creds("ANALYST_PROFILES")

    def sso_configured(self) -> bool:
        return bool(self.EXTERNAL_SSO_URL and self.EXTERNAL_SSO_SECRET)


settings = Settings()
