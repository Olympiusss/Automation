"""
SentinelOne 24/7 Monitoring Daemon
Polls the platform every 30s, detects Critical/High incidents,
creates Zoho tickets, and sends MS Teams notifications.

Usage:
    python sentinel_monitor.py              # Run continuously
    python sentinel_monitor.py --once       # Single poll cycle
    python sentinel_monitor.py --dry-run    # No ticket/notification, just log
"""

import os
import sys
import json
import time
import signal
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import Set

# Setup path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from soc_config import (
    MONITOR_CONFIG, S1_API_TOKEN, S1_BASE_URL,
    ZOHO_CONFIG, TEAMS_WEBHOOK_URL,
)
from s1_client import S1Client
from zoho_client import ZohoClient
from teams_notify import send_incident_card, send_status_message

# ─────────────────────────────────────────
# Logging
# ─────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("monitor.log", encoding="utf-8"),
    ]
)
logger = logging.getLogger("sentinel_monitor")


class SentinelMonitor:
    """24/7 SentinelOne monitoring daemon."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.running = True

        # Config
        self.poll_interval = MONITOR_CONFIG.get("poll_interval_seconds", 30)
        self.severity_thresholds = MONITOR_CONFIG.get("severity_thresholds", ["Critical", "High"])
        self.lookback_seconds = MONITOR_CONFIG.get("lookback_seconds", 60)
        self.max_tickets_per_hour = MONITOR_CONFIG.get("max_tickets_per_hour", 30)
        self.state_file = MONITOR_CONFIG.get("state_file", "monitor_state.json")
        self.log_file = MONITOR_CONFIG.get("log_file", "monitor_log.json")
        self.site_cache_ttl = MONITOR_CONFIG.get("site_cache_ttl_seconds", 300)

        # Clients
        self.s1 = S1Client(base_url=S1_BASE_URL, api_token=S1_API_TOKEN)
        self.zoho = ZohoClient(ZOHO_CONFIG) if not dry_run else None
        self.webhook_url = TEAMS_WEBHOOK_URL

        # State
        self.processed_ids: Set[str] = set()
        self.tickets_this_hour = 0
        self.hour_start = time.time()
        self._sites_cache = None
        self._sites_cache_time = 0

        # Load persisted state
        self._load_state()

        # Handle shutdown
        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _shutdown(self, signum, frame):
        logger.info("Shutdown signal received, saving state...")
        self._save_state()
        self.running = False

    # ─────────────────────────────────────
    # State Persistence
    # ─────────────────────────────────────

    def _load_state(self):
        """Load processed IDs from disk."""
        try:
            if os.path.exists(self.state_file):
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                self.processed_ids = set(data.get("processed_ids", []))
                logger.info(f"Loaded {len(self.processed_ids)} processed IDs from state")
        except Exception as e:
            logger.warning(f"Could not load state: {e}")

    def _save_state(self):
        """Persist processed IDs to disk."""
        try:
            # Keep only last 10000 IDs to prevent unbounded growth
            ids_list = list(self.processed_ids)
            if len(ids_list) > 10000:
                ids_list = ids_list[-10000:]
                self.processed_ids = set(ids_list)

            with open(self.state_file, "w") as f:
                json.dump({
                    "processed_ids": ids_list,
                    "last_saved": datetime.now(timezone.utc).isoformat(),
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save state: {e}")

    def _log_action(self, action: str, details: dict):
        """Append to the action log."""
        try:
            log_entries = []
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as f:
                    log_entries = json.load(f)

            log_entries.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "dry_run": self.dry_run,
                **details,
            })

            # Keep last 1000 entries
            if len(log_entries) > 1000:
                log_entries = log_entries[-1000:]

            with open(self.log_file, "w") as f:
                json.dump(log_entries, f, indent=2)
        except Exception as e:
            logger.error(f"Could not write log: {e}")

    # ─────────────────────────────────────
    # Site Caching
    # ─────────────────────────────────────

    def _get_sites(self):
        """Get sites, cached with TTL."""
        now = time.time()
        if self._sites_cache and (now - self._sites_cache_time) < self.site_cache_ttl:
            return self._sites_cache

        try:
            self._sites_cache = self.s1.get_sites()
            self._sites_cache_time = now
            logger.info(f"Refreshed site cache: {len(self._sites_cache)} sites")
        except Exception as e:
            logger.error(f"Failed to fetch sites: {e}")
            if self._sites_cache:
                return self._sites_cache
            return []

        return self._sites_cache

    # ─────────────────────────────────────
    # Rate Limiting
    # ─────────────────────────────────────

    def _check_ticket_rate(self) -> bool:
        """Check if we're within the hourly ticket creation limit."""
        now = time.time()
        if now - self.hour_start >= 3600:
            self.tickets_this_hour = 0
            self.hour_start = now

        return self.tickets_this_hour < self.max_tickets_per_hour

    # ─────────────────────────────────────
    # Severity Check
    # ─────────────────────────────────────

    def _is_actionable(self, item: dict, item_type: str = "threat") -> bool:
        """Check if a threat/alert meets severity criteria."""
        if item_type == "threat":
            ti = item.get("threatInfo", item)
            severity = str(ti.get("analystVerdictDescription",
                                   ti.get("severity",
                                          ti.get("confidenceLevel", "")))).strip()
        else:
            severity = str(item.get("severity", "")).strip()

        # Check case-insensitive match
        for threshold in self.severity_thresholds:
            if threshold.lower() in severity.lower():
                return True

        return False

    # ─────────────────────────────────────
    # Incident Extraction
    # ─────────────────────────────────────

    def _extract_incident(self, item: dict, item_type: str = "threat") -> dict:
        """Extract standardized incident data from a threat or alert."""
        if item_type == "threat":
            ti = item.get("threatInfo", item)
            ari = item.get("agentRealtimeInfo", item.get("agentDetectionInfo", {}))
            return {
                "threat_id": str(item.get("id", ti.get("id", ""))),
                "threat_name": ti.get("threatName", ti.get("displayName", ti.get("classification", "Unknown"))),
                "classification": ti.get("classification", ""),
                "severity": ti.get("analystVerdictDescription", ti.get("severity", "High")),
                "mitigation_status": ti.get("mitigationStatusDescription", ti.get("mitigationStatus", "")),
                "endpoint": ari.get("agentComputerName", ari.get("computerName", "")),
                "site_name": ari.get("siteName", item.get("siteName", "")),
                "file_path": ti.get("filePath", ""),
                "sha256": ti.get("sha256", ti.get("fileSha256", "")),
                "process_name": ti.get("originatorProcess", ti.get("processName", "")),
                "detected_at": ti.get("createdAt", ti.get("identifiedAt", "")),
                "mitre_tactics": item.get("mitreTactics", []),
            }
        else:
            # Alert
            return {
                "threat_id": str(item.get("id", "")),
                "threat_name": item.get("ruleName", item.get("alertName", "Alert")),
                "classification": "Cloud Detection Alert",
                "severity": item.get("severity", "High"),
                "mitigation_status": item.get("analystVerdict", ""),
                "endpoint": item.get("agentComputerName", item.get("endpoint", "")),
                "site_name": item.get("siteName", ""),
                "file_path": "",
                "sha256": item.get("sourceProcessFileHashSha256", ""),
                "process_name": item.get("sourceProcessName", ""),
                "detected_at": item.get("createdAt", ""),
                "mitre_tactics": [],
            }

    # ─────────────────────────────────────
    # Main Poll Cycle
    # ─────────────────────────────────────

    def poll_once(self):
        """Execute a single poll cycle across all sites."""
        sites = self._get_sites()
        if not sites:
            logger.warning("No sites available")
            return

        now = datetime.now(timezone.utc)
        lookback = now - timedelta(seconds=self.lookback_seconds)
        start_iso = lookback.isoformat()
        end_iso = now.isoformat()

        new_incidents = 0

        for site in sites:
            site_name = site.get("name", "Unknown")
            site_id = str(site.get("id", ""))
            if not site_id:
                continue

            try:
                # Fetch recent threats
                threats = self.s1.get_threats(
                    site_id, start_iso=start_iso, end_iso=end_iso
                )

                for t in threats:
                    t_id = str(t.get("id", t.get("threatInfo", {}).get("id", "")))
                    if t_id in self.processed_ids:
                        continue
                    if not self._is_actionable(t, "threat"):
                        self.processed_ids.add(t_id)
                        continue

                    # New actionable threat
                    incident = self._extract_incident(t, "threat")
                    if not incident.get("site_name"):
                        incident["site_name"] = site_name

                    self._handle_incident(incident)
                    self.processed_ids.add(t_id)
                    new_incidents += 1

                # Fetch recent alerts
                alerts = self.s1.get_alerts(
                    site_id, start_iso=start_iso, end_iso=end_iso
                )

                for a in alerts:
                    a_id = f"alert-{a.get('id', '')}"
                    if a_id in self.processed_ids:
                        continue
                    if not self._is_actionable(a, "alert"):
                        self.processed_ids.add(a_id)
                        continue

                    incident = self._extract_incident(a, "alert")
                    if not incident.get("site_name"):
                        incident["site_name"] = site_name

                    self._handle_incident(incident)
                    self.processed_ids.add(a_id)
                    new_incidents += 1

                # Small delay between sites to respect rate limits
                time.sleep(0.2)

            except Exception as e:
                logger.error(f"Error polling site {site_name}: {e}")

        if new_incidents > 0:
            logger.info(f"Poll cycle: {new_incidents} new incidents processed")
            self._save_state()
        else:
            logger.debug("Poll cycle: no new incidents")

    def _handle_incident(self, incident: dict):
        """Process a new incident: create ticket + send notification."""
        severity = incident.get("severity", "High")
        threat_name = incident.get("threat_name", "Unknown")
        endpoint = incident.get("endpoint", "Unknown")
        site_name = incident.get("site_name", "Unknown")

        logger.info(
            f"{'[DRY-RUN] ' if self.dry_run else ''}"
            f"New {severity} incident: {threat_name} on {endpoint} ({site_name})"
        )

        zoho_ticket = None

        # Create Zoho ticket
        if not self.dry_run and self._check_ticket_rate():
            try:
                zoho_ticket = self.zoho.create_incident_ticket(incident)
                if zoho_ticket.get("success"):
                    self.tickets_this_hour += 1
                    logger.info(f"Zoho ticket created: #{zoho_ticket.get('ticket_number')}")
                else:
                    logger.error(f"Zoho ticket failed: {zoho_ticket.get('error')}")
            except Exception as e:
                logger.error(f"Zoho ticket error: {e}")

        # Send Teams notification
        if not self.dry_run and self.webhook_url:
            try:
                send_incident_card(incident, zoho_ticket, self.webhook_url)
            except Exception as e:
                logger.error(f"Teams notification error: {e}")

        # Log action
        self._log_action("incident_detected", {
            "threat_id": incident.get("threat_id"),
            "threat_name": threat_name,
            "severity": severity,
            "endpoint": endpoint,
            "site_name": site_name,
            "zoho_ticket": zoho_ticket.get("ticket_number") if zoho_ticket else None,
        })

    # ─────────────────────────────────────
    # Run Loop
    # ─────────────────────────────────────

    def run(self, once: bool = False):
        """Start the monitoring loop."""
        mode = "DRY-RUN" if self.dry_run else "LIVE"
        logger.info(f"=== SentinelOne Monitor Starting ({mode}) ===")
        logger.info(f"Poll interval: {self.poll_interval}s | "
                     f"Severity: {self.severity_thresholds} | "
                     f"Lookback: {self.lookback_seconds}s")

        if not self.dry_run and self.webhook_url:
            send_status_message(
                f"🟢 SOC Monitor started ({mode}). "
                f"Polling every {self.poll_interval}s for {', '.join(self.severity_thresholds)} incidents.",
                self.webhook_url,
            )

        if once:
            self.poll_once()
            logger.info("Single poll completed. Exiting.")
            return

        while self.running:
            try:
                self.poll_once()
            except Exception as e:
                logger.error(f"Unhandled error in poll cycle: {e}")

            # Wait for next cycle
            for _ in range(int(self.poll_interval * 10)):
                if not self.running:
                    break
                time.sleep(0.1)

        self._save_state()
        logger.info("=== SentinelOne Monitor Stopped ===")

        if not self.dry_run and self.webhook_url:
            send_status_message("🔴 SOC Monitor stopped.", self.webhook_url)


# ─────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────

def _load_secrets_for_daemon():
    """Load secrets from .streamlit/secrets.toml for non-Streamlit execution."""
    import soc_config
    secrets_path = os.path.join(os.path.dirname(__file__), ".streamlit", "secrets.toml")
    if not os.path.exists(secrets_path):
        return

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.warning("No TOML parser available. Install tomli: pip install tomli")
            return

    with open(secrets_path, "rb") as f:
        secrets = tomllib.load(f)

    general = secrets.get("general", {})
    zoho = secrets.get("zoho", {})
    teams = secrets.get("teams", {})

    soc_config.S1_API_TOKEN = general.get("api_token", soc_config.S1_API_TOKEN)
    soc_config.TEAMS_WEBHOOK_URL = teams.get("webhook_url", soc_config.TEAMS_WEBHOOK_URL)

    soc_config.ZOHO_CONFIG["client_id"] = zoho.get("client_id", "")
    soc_config.ZOHO_CONFIG["client_secret"] = zoho.get("client_secret", "")
    soc_config.ZOHO_CONFIG["refresh_token"] = zoho.get("refresh_token", "")
    soc_config.ZOHO_CONFIG["org_id"] = zoho.get("org_id", "")
    soc_config.ZOHO_CONFIG["department_id"] = zoho.get("department_id", "")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelOne 24/7 Monitoring Daemon")
    parser.add_argument("--once", action="store_true", help="Run a single poll cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="No tickets/notifications, just log")
    args = parser.parse_args()

    _load_secrets_for_daemon()

    monitor = SentinelMonitor(dry_run=args.dry_run)
    monitor.run(once=args.once)
