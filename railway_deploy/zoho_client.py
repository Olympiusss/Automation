"""
Zoho Desk API Client — OAuth 2.0 Ticket Management
Creates incident tickets from SentinelOne alerts.
"""

import time
import json
import logging
import requests
from typing import Optional, Dict, Any

from soc_config import ZOHO_CONFIG, SEVERITY_TO_PRIORITY

logger = logging.getLogger("zoho_client")


class ZohoClient:
    """Zoho Desk REST API client with OAuth 2.0 refresh token flow."""

    def __init__(self, config: dict = None):
        cfg = config or ZOHO_CONFIG
        self.accounts_url = cfg.get("accounts_url", "https://accounts.zoho.com")
        self.desk_url = cfg.get("desk_url", "https://desk.zoho.com/api/v1")
        self.client_id = cfg.get("client_id", "")
        self.client_secret = cfg.get("client_secret", "")
        self.refresh_token = cfg.get("refresh_token", "")
        self.org_id = cfg.get("org_id", "")
        self.department_id = cfg.get("department_id", "")

        self._access_token = ""
        self._token_expires_at = 0

    # ─────────────────────────────────────
    # OAuth Token Management
    # ─────────────────────────────────────

    def _refresh_access_token(self):
        """Get a new access token using the refresh token."""
        url = f"{self.accounts_url}/oauth/v2/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
        }

        try:
            resp = requests.post(url, data=data, timeout=15)
            if resp.status_code == 200:
                body = resp.json()
                self._access_token = body.get("access_token", "")
                # Tokens typically expire in 3600s; refresh 5 min early
                self._token_expires_at = time.time() + body.get("expires_in", 3600) - 300
                logger.info("Zoho access token refreshed")
                return True
            else:
                logger.error(f"Zoho token refresh failed: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Zoho token refresh error: {e}")
            return False

    def _get_token(self) -> str:
        """Get a valid access token, refreshing if needed."""
        if not self._access_token or time.time() >= self._token_expires_at:
            self._refresh_access_token()
        return self._access_token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Zoho-oauthtoken {self._get_token()}",
            "Content-Type": "application/json",
            "orgId": self.org_id,
        }

    # ─────────────────────────────────────
    # Ticket Operations
    # ─────────────────────────────────────

    def create_ticket(
        self,
        subject: str,
        description: str,
        priority: str = "High",
        category: str = "Security Incident",
        contact_email: str = None,
        extra_fields: dict = None,
    ) -> Dict[str, Any]:
        """
        Create a Zoho Desk ticket.

        Returns:
            {"success": bool, "ticket_id": str, "ticket_number": str, "url": str}
        """
        url = f"{self.desk_url}/tickets"

        payload = {
            "subject": subject,
            "description": description,
            "priority": priority,
            "category": category,
            "status": "Open",
        }

        if self.department_id:
            payload["departmentId"] = self.department_id

        if contact_email:
            payload["email"] = contact_email

        if extra_fields:
            payload.update(extra_fields)

        try:
            resp = requests.post(url, headers=self._headers(),
                                 json=payload, timeout=15)

            if resp.status_code in (200, 201):
                body = resp.json()
                ticket_id = str(body.get("id", ""))
                ticket_number = body.get("ticketNumber", "")
                ticket_url = f"https://desk.zoho.com/agent/{self.org_id}/tickets/{ticket_id}"

                logger.info(f"Zoho ticket created: #{ticket_number} ({ticket_id})")
                return {
                    "success": True,
                    "ticket_id": ticket_id,
                    "ticket_number": ticket_number,
                    "url": ticket_url,
                }
            else:
                error_msg = resp.text[:300]
                logger.error(f"Zoho create ticket failed: {resp.status_code} {error_msg}")
                return {"success": False, "error": error_msg}

        except Exception as e:
            logger.error(f"Zoho create ticket error: {e}")
            return {"success": False, "error": str(e)}

    def add_comment(self, ticket_id: str, comment: str, is_public: bool = False) -> bool:
        """Add a comment to an existing ticket."""
        url = f"{self.desk_url}/tickets/{ticket_id}/comments"
        payload = {
            "content": comment,
            "isPublic": is_public,
        }

        try:
            resp = requests.post(url, headers=self._headers(),
                                 json=payload, timeout=15)
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.error(f"Zoho add comment error: {e}")
            return False

    # ─────────────────────────────────────
    # Incident → Ticket Builder
    # ─────────────────────────────────────

    def create_incident_ticket(self, incident: dict) -> Dict[str, Any]:
        """
        Create a ticket from a SentinelOne incident.

        Args:
            incident: dict with keys like threat_name, severity, endpoint,
                      site_name, classification, sha256, file_path, etc.
        """
        severity = incident.get("severity", "High")
        threat_name = incident.get("threat_name", "Unknown Threat")
        endpoint = incident.get("endpoint", "Unknown")
        site_name = incident.get("site_name", "Unknown Site")
        classification = incident.get("classification", "")

        subject = f"[S1-{severity}] {threat_name} on {endpoint} — {site_name}"

        description = f"""<h2>🛡️ SentinelOne Security Incident</h2>

<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;">
<tr><td><b>Severity</b></td><td>{severity}</td></tr>
<tr><td><b>Threat Name</b></td><td>{threat_name}</td></tr>
<tr><td><b>Classification</b></td><td>{classification}</td></tr>
<tr><td><b>Endpoint</b></td><td>{endpoint}</td></tr>
<tr><td><b>Site</b></td><td>{site_name}</td></tr>
<tr><td><b>File Path</b></td><td>{incident.get('file_path', 'N/A')}</td></tr>
<tr><td><b>SHA256</b></td><td>{incident.get('sha256', 'N/A')}</td></tr>
<tr><td><b>Mitigation Status</b></td><td>{incident.get('mitigation_status', 'N/A')}</td></tr>
<tr><td><b>Process</b></td><td>{incident.get('process_name', 'N/A')}</td></tr>
<tr><td><b>Detected At</b></td><td>{incident.get('detected_at', 'N/A')}</td></tr>
<tr><td><b>Threat ID</b></td><td>{incident.get('threat_id', 'N/A')}</td></tr>
</table>

<p><b>MITRE ATT&CK:</b> {', '.join(str(m) for m in incident.get('mitre_tactics', [])[:5]) or 'N/A'}</p>

<p><i>Auto-generated by SentinelOne SOC Agent</i></p>
"""

        priority = SEVERITY_TO_PRIORITY.get(severity, "Medium")

        return self.create_ticket(
            subject=subject,
            description=description,
            priority=priority,
            category="Security Incident",
        )
