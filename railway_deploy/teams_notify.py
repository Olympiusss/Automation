"""
MS Teams Notification — Adaptive Card Webhooks
Sends rich incident cards to Microsoft Teams channels.
"""

import logging
import requests
from typing import Dict, Any

from soc_config import TEAMS_WEBHOOK_URL, SEVERITY_COLORS

logger = logging.getLogger("teams_notify")


def send_incident_card(
    incident: dict,
    zoho_ticket: dict = None,
    webhook_url: str = None,
) -> bool:
    """
    Send a rich Adaptive Card to MS Teams for a security incident.

    Args:
        incident: dict with threat_name, severity, endpoint, site_name, etc.
        zoho_ticket: optional dict with ticket_id, ticket_number, url
        webhook_url: override webhook URL (default from config)

    Returns:
        True if sent successfully
    """
    url = webhook_url or TEAMS_WEBHOOK_URL
    if not url:
        logger.error("No Teams webhook URL configured")
        return False

    severity = incident.get("severity", "High")
    threat_name = incident.get("threat_name", "Unknown Threat")
    endpoint = incident.get("endpoint", "Unknown")
    site_name = incident.get("site_name", "Unknown Site")
    classification = incident.get("classification", "")
    detected_at = incident.get("detected_at", "N/A")
    mitigation = incident.get("mitigation_status", "N/A")
    sha256 = incident.get("sha256", "N/A")
    file_path = incident.get("file_path", "N/A")
    threat_id = incident.get("threat_id", "")

    # Severity → color
    accent_color = SEVERITY_COLORS.get(severity, "default")
    severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🔵", "Low": "🟢"}.get(severity, "⚪")

    # Build Adaptive Card
    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "Container",
                            "style": accent_color,
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": f"{severity_emoji} SentinelOne Alert — {severity}",
                                    "weight": "bolder",
                                    "size": "large",
                                    "color": accent_color,
                                }
                            ],
                            "bleed": True,
                        },
                        {
                            "type": "TextBlock",
                            "text": threat_name,
                            "weight": "bolder",
                            "size": "medium",
                            "wrap": True,
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Severity", "value": f"{severity_emoji} {severity}"},
                                {"title": "Classification", "value": classification or "N/A"},
                                {"title": "Endpoint", "value": endpoint},
                                {"title": "Site", "value": site_name},
                                {"title": "File Path", "value": file_path[:80]},
                                {"title": "SHA256", "value": sha256[:32] + "..." if len(sha256) > 32 else sha256},
                                {"title": "Mitigation", "value": mitigation},
                                {"title": "Detected", "value": detected_at},
                            ],
                        },
                    ],
                    "actions": [],
                }
            }
        ]
    }

    # Add Zoho ticket link if available
    if zoho_ticket and zoho_ticket.get("success"):
        card["attachments"][0]["content"]["body"].append({
            "type": "TextBlock",
            "text": f"📋 Zoho Ticket: #{zoho_ticket.get('ticket_number', 'N/A')}",
            "weight": "bolder",
            "spacing": "medium",
        })
        if zoho_ticket.get("url"):
            card["attachments"][0]["content"]["actions"].append({
                "type": "Action.OpenUrl",
                "title": "View Zoho Ticket",
                "url": zoho_ticket["url"],
            })

    # Add S1 console link
    if threat_id:
        card["attachments"][0]["content"]["actions"].append({
            "type": "Action.OpenUrl",
            "title": "View in SentinelOne",
            "url": f"https://euce1-exclusive.sentinelone.net/incidents/threats/{threat_id}/overview",
        })

    # Send
    try:
        resp = requests.post(url, json=card, timeout=10)
        if resp.status_code in (200, 202):
            logger.info(f"Teams notification sent: {threat_name} on {endpoint}")
            return True
        else:
            logger.error(f"Teams webhook failed: {resp.status_code} {resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Teams notification error: {e}")
        return False


def send_status_message(message: str, webhook_url: str = None) -> bool:
    """Send a simple text message to Teams (for monitor status updates)."""
    url = webhook_url or TEAMS_WEBHOOK_URL
    if not url:
        return False

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🛡️ SOC Agent Monitor",
                            "weight": "bolder",
                            "size": "medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": message,
                            "wrap": True,
                        },
                    ]
                }
            }
        ]
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        return resp.status_code in (200, 202)
    except Exception:
        return False
