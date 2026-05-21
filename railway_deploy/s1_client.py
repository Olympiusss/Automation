"""
SentinelOne API v2.1 — Direct Platform Client
No Streamlit dependency. Pure Python. Rate-limit aware.
"""

import time
import json
import requests
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from soc_config import (
    S1_BASE_URL, S1_API_TOKEN, S1_REQUEST_TIMEOUT,
    S1_RATE_LIMIT_RETRY_DELAY, S1_MAX_RETRIES,
    S1_PAGE_SIZE, S1_PAGINATION_DELAY,
)

logger = logging.getLogger("s1_client")


class S1Client:
    """Direct SentinelOne API v2.1 client."""

    def __init__(self, base_url: str = None, api_token: str = None):
        self.base_url = (base_url or S1_BASE_URL).rstrip("/")
        self.api_token = api_token or S1_API_TOKEN
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"ApiToken {self.api_token}",
            "Content-Type": "application/json",
        })

    # ─────────────────────────────────────────
    # Low-level HTTP (rate-limit aware)
    # ─────────────────────────────────────────

    def _get(self, endpoint: str, params: dict = None, timeout: int = None) -> dict:
        """GET with retry on 429."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        timeout = timeout or S1_REQUEST_TIMEOUT

        for attempt in range(S1_MAX_RETRIES):
            try:
                resp = self._session.get(url, params=params, timeout=timeout)
            except requests.exceptions.RequestException as e:
                if attempt < S1_MAX_RETRIES - 1:
                    time.sleep(S1_RATE_LIMIT_RETRY_DELAY * (attempt + 1))
                    continue
                raise RuntimeError(f"Network error on {endpoint}: {e}")

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = S1_RATE_LIMIT_RETRY_DELAY * (attempt + 1)
                logger.warning(f"Rate limited on {endpoint}, waiting {wait}s")
                time.sleep(wait)
                continue
            elif resp.status_code == 401:
                raise RuntimeError(f"Auth failed on {endpoint}: 401 Unauthorized")
            else:
                raise RuntimeError(
                    f"API error on {endpoint}: {resp.status_code} {resp.text[:300]}"
                )

        raise RuntimeError(f"Exhausted retries on {endpoint}")

    def _post(self, endpoint: str, payload: dict, timeout: int = None) -> dict:
        """POST with retry on 429."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        timeout = timeout or S1_REQUEST_TIMEOUT

        for attempt in range(S1_MAX_RETRIES):
            try:
                resp = self._session.post(url, json=payload, timeout=timeout)
            except requests.exceptions.RequestException as e:
                if attempt < S1_MAX_RETRIES - 1:
                    time.sleep(S1_RATE_LIMIT_RETRY_DELAY * (attempt + 1))
                    continue
                raise RuntimeError(f"Network error on {endpoint}: {e}")

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 429:
                wait = S1_RATE_LIMIT_RETRY_DELAY * (attempt + 1)
                logger.warning(f"Rate limited on POST {endpoint}, waiting {wait}s")
                time.sleep(wait)
                continue
            else:
                raise RuntimeError(
                    f"API error on POST {endpoint}: {resp.status_code} {resp.text[:300]}"
                )

        raise RuntimeError(f"Exhausted retries on POST {endpoint}")

    # ─────────────────────────────────────────
    # Cursor Pagination
    # ─────────────────────────────────────────

    def _paginate(self, endpoint: str, params: dict = None,
                  data_key: str = None, limit: int = 0) -> List[dict]:
        """
        Auto-paginate a GET endpoint using cursor pagination.
        limit=0 means fetch ALL pages.
        """
        if params is None:
            params = {}
        params = params.copy()
        if "limit" not in params:
            params["limit"] = S1_PAGE_SIZE

        all_items = []
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor

            body = self._get(endpoint, params)

            # Extract data — handle various response shapes
            data = body.get("data", body)
            if isinstance(data, dict):
                if data_key and data_key in data:
                    items = data[data_key]
                elif "sites" in data:
                    items = data["sites"]
                else:
                    items = [data]
            elif isinstance(data, list):
                items = data
            else:
                break

            all_items.extend(items)

            # Check hard limit
            if limit and len(all_items) >= limit:
                all_items = all_items[:limit]
                break

            # Next page
            pagination = body.get("pagination", {}) or {}
            cursor = pagination.get("nextCursor")
            if not cursor:
                break

            time.sleep(S1_PAGINATION_DELAY)

        return all_items

    # ─────────────────────────────────────────
    # Sites
    # ─────────────────────────────────────────

    def get_sites(self) -> List[dict]:
        """Fetch all sites on the platform."""
        return self._paginate("sites")

    def find_site(self, name: str) -> Optional[dict]:
        """Find a site by name (case-insensitive partial match)."""
        sites = self.get_sites()
        name_lower = name.lower().strip()
        # Exact match first
        for s in sites:
            if s.get("name", "").lower() == name_lower:
                return s
        # Partial match
        for s in sites:
            sn = s.get("name", "").lower()
            if name_lower in sn or sn in name_lower:
                return s
        return None

    def get_site_id(self, name: str) -> Optional[str]:
        """Resolve site name → site ID."""
        site = self.find_site(name)
        return str(site["id"]) if site else None

    # ─────────────────────────────────────────
    # Agents / Endpoints
    # ─────────────────────────────────────────

    def get_agents(self, site_id: str = None, filters: dict = None) -> List[dict]:
        """Fetch agents. Optional site_id filter."""
        params = filters.copy() if filters else {}
        if site_id:
            params["siteIds"] = site_id
        return self._paginate("agents", params)

    def get_agent_by_name(self, name: str, site_id: str = None) -> List[dict]:
        """Find agents by computer name (partial match)."""
        agents = self.get_agents(site_id)
        name_lower = name.lower()
        return [
            a for a in agents
            if name_lower in a.get("computerName", "").lower()
        ]

    # ─────────────────────────────────────────
    # Threats
    # ─────────────────────────────────────────

    def get_threats(self, site_id: str = None, start_iso: str = None,
                    end_iso: str = None, severity: str = None,
                    limit: int = 0) -> List[dict]:
        """Fetch threats with optional filters."""
        params = {
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }
        if site_id:
            params["siteIds"] = site_id
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        if severity:
            # S1 uses analystVerdict filter, not a severity param directly
            # For confidence-based filtering we handle post-fetch
            pass
        return self._paginate("threats", params, limit=limit)

    def get_threat_detail(self, threat_id: str) -> Optional[dict]:
        """Fetch full detail for a single threat."""
        try:
            body = self._get(f"threats", params={"ids": threat_id})
            data = body.get("data", [])
            if isinstance(data, list) and data:
                return data[0]
            return data if isinstance(data, dict) else None
        except Exception as e:
            logger.error(f"Failed to get threat {threat_id}: {e}")
            return None

    # ─────────────────────────────────────────
    # Alerts (Cloud Detection)
    # ─────────────────────────────────────────

    def get_alerts(self, site_id: str = None, start_iso: str = None,
                   end_iso: str = None, severity: str = None,
                   limit: int = 0) -> List[dict]:
        """Fetch cloud detection alerts."""
        params = {
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }
        if site_id:
            params["siteIds"] = site_id
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        if severity:
            params["severity"] = severity
        return self._paginate("cloud-detection/alerts", params, limit=limit)

    # ─────────────────────────────────────────
    # Activities (Audit Trail)
    # ─────────────────────────────────────────

    def get_activities(self, site_id: str = None, start_iso: str = None,
                       end_iso: str = None, activity_types: str = None,
                       limit: int = 0) -> List[dict]:
        """Fetch activity/audit trail."""
        params = {
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }
        if site_id:
            params["siteIds"] = site_id
        if start_iso:
            params["createdAt__gte"] = start_iso
        if end_iso:
            params["createdAt__lte"] = end_iso
        if activity_types:
            params["activityTypes"] = activity_types
        return self._paginate("activities", params, limit=limit)

    # ─────────────────────────────────────────
    # Exclusions & Blocklist
    # ─────────────────────────────────────────

    def get_exclusions(self, site_id: str) -> List[dict]:
        """Fetch exclusion/whitelist rules."""
        return self._paginate("exclusions", {"siteIds": site_id})

    def get_blocklist(self, site_id: str) -> List[dict]:
        """Fetch hash blocklist restrictions."""
        return self._paginate("restrictions", {
            "siteIds": site_id,
            "type": "black_hash",
            "includeParents": "true",
            "includeChildren": "true",
        })

    # ─────────────────────────────────────────
    # Application Risk / Vulnerabilities
    # ─────────────────────────────────────────

    def get_vulnerabilities(self, site_id: str = None, risk_level: str = None, limit: int = 0) -> List[dict]:
        """Fetch vulnerable applications. Often requires Application Risk module enabled."""
        params = {}
        if site_id:
            params["siteIds"] = site_id
        if risk_level:
            params["riskLevel"] = risk_level
            
        try:
            return self._paginate("application-management/risks", params, limit=limit)
        except Exception as e:
            if "404" in str(e):
                logger.warning("application-management/risks not found, trying installed-applications")
                return self._paginate("installed-applications", params, limit=limit)
            raise

    def get_cve_details(self, site_id: str = None, cve_id: str = None, limit: int = 0) -> List[dict]:
        """Fetch CVE details across endpoints."""
        params = {}
        if site_id:
            params["siteIds"] = site_id
        if cve_id:
            params["cveId"] = cve_id
            
        try:
            return self._paginate("application-management/cves", params, limit=limit)
        except Exception as e:
            if "404" in str(e):
                return self._paginate("installed-applications/cves", params, limit=limit)
            raise

    # ─────────────────────────────────────────
    # Deep Visibility (Async Query)
    # ─────────────────────────────────────────

    def dv_query(self, s1ql: str, site_id: str = None,
                 from_date: str = None, to_date: str = None,
                 limit: int = 100, poll_timeout: int = 60) -> List[dict]:
        """
        Run a Deep Visibility query using S1QL.
        Handles the async init → poll → fetch events flow.

        Args:
            s1ql: S1QL query string (e.g. 'ObjectType = "process"')
            site_id: Optional site scope
            from_date: ISO datetime string
            to_date: ISO datetime string
            limit: Max events to return
            poll_timeout: Max seconds to wait for query completion

        Returns:
            List of DV event dicts
        """
        # Step 1: Init query
        payload = {
            "query": s1ql,
            "fromDate": from_date or "",
            "toDate": to_date or "",
            "limit": min(limit, 1000),
        }
        if site_id:
            payload["siteIds"] = [site_id]

        try:
            init_resp = self._post("dv/init-query", payload)
        except RuntimeError as e:
            logger.error(f"DV init-query failed: {e}")
            return []

        query_id = init_resp.get("data", {}).get("queryId")
        if not query_id:
            logger.error("DV init-query returned no queryId")
            return []

        # Step 2: Poll for completion
        start_time = time.time()
        while (time.time() - start_time) < poll_timeout:
            time.sleep(2)
            try:
                status_resp = self._get("dv/query-status", {"queryId": query_id})
                state = status_resp.get("data", {}).get("responseState", "")
                if state == "FINISHED":
                    break
                elif state == "FAILED":
                    logger.error("DV query FAILED")
                    return []
            except RuntimeError:
                continue

        # Step 3: Fetch events
        try:
            events_resp = self._get("dv/events", {
                "queryId": query_id,
                "limit": limit,
            })
            return events_resp.get("data", [])
        except RuntimeError as e:
            logger.error(f"DV events fetch failed: {e}")
            return []

    # ─────────────────────────────────────────
    # Deep Visibility — Process Chain
    # ─────────────────────────────────────────

    def get_process_chain(self, site_id: str, process_name: str = None,
                          sha256: str = None, pid: str = None,
                          from_date: str = None, to_date: str = None) -> List[dict]:
        """
        Query Deep Visibility for process chain details.
        Returns events with source process, parent process, and command lines.
        """
        # Build S1QL query
        conditions = ['ObjectType = "process"']
        if process_name:
            conditions.append(f'ProcessName contains "{process_name}"')
        if sha256:
            conditions.append(f'FileSHA256 = "{sha256}"')
        if pid:
            conditions.append(f'SrcProcPID = "{pid}"')

        s1ql = " AND ".join(conditions)

        # Default to last 24h if no dates
        if not from_date:
            from_date = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        if not to_date:
            to_date = datetime.now(timezone.utc).isoformat()

        events = self.dv_query(s1ql, site_id=site_id,
                               from_date=from_date, to_date=to_date,
                               limit=200)

        # Extract process chain fields
        chain_data = []
        for ev in events:
            chain_data.append({
                "event_time": ev.get("eventTime", ev.get("createdAt", "")),
                "endpoint": ev.get("endpointName", ev.get("agentName", "")),
                "src_process": ev.get("srcProcName", ev.get("processName", "")),
                "src_cmd_line": ev.get("srcProcCmdLine", ev.get("processCmd", "")),
                "src_pid": ev.get("srcProcPid", ""),
                "src_image_path": ev.get("srcProcImagePath", ""),
                "src_sha256": ev.get("srcProcImageSha256", ""),
                "src_user": ev.get("srcProcUser", ""),
                "parent_process": ev.get("parentProcessName",
                                         ev.get("srcProcParentName", "")),
                "parent_cmd_line": ev.get("parentProcessCmdLine",
                                          ev.get("srcProcParentCmdLine", "")),
                "parent_pid": ev.get("parentPid",
                                      ev.get("srcProcParentPid", "")),
                "parent_image_path": ev.get("srcProcParentImagePath", ""),
                "parent_sha256": ev.get("srcProcParentImageSha256", ""),
                "grandparent_process": ev.get("srcProcParentParentName",
                                               ev.get("tgtProcName", "")),
                "event_type": ev.get("eventType", ""),
                "site_name": ev.get("siteName", ""),
            })

        return chain_data

    def backtrack_ioc(self, site_id: str, ioc_type: str, ioc_value: str,
                      days_back: int = 14) -> List[dict]:
        """
        Retroactive hunt across all endpoints for an IOC.

        Args:
            site_id: Site to search in
            ioc_type: One of 'sha256', 'process_name', 'cmdline', 'filepath'
            ioc_value: The IOC value to hunt for
            days_back: Number of days to look back (default 14)

        Returns:
            List of matching DV events sorted by time
        """
        from_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
        to_date = datetime.now(timezone.utc).isoformat()

        # Build S1QL based on IOC type
        ioc_queries = {
            "sha256": f'FileSHA256 = "{ioc_value}" OR SrcProcImageSha256 = "{ioc_value}"',
            "process_name": f'ProcessName contains "{ioc_value}" OR SrcProcName contains "{ioc_value}"',
            "cmdline": f'SrcProcCmdLine contains "{ioc_value}" OR ProcessCmd contains "{ioc_value}"',
            "filepath": f'FilePath contains "{ioc_value}" OR SrcProcImagePath contains "{ioc_value}"',
        }

        s1ql = ioc_queries.get(ioc_type)
        if not s1ql:
            logger.error(f"Unknown IOC type: {ioc_type}")
            return []

        events = self.dv_query(s1ql, site_id=site_id,
                               from_date=from_date, to_date=to_date,
                               limit=500)

        # Normalize and sort by time
        results = []
        for ev in events:
            results.append({
                "event_time": ev.get("eventTime", ev.get("createdAt", "")),
                "endpoint": ev.get("endpointName", ev.get("agentName", "")),
                "event_type": ev.get("eventType", ""),
                "process_name": ev.get("srcProcName", ev.get("processName", "")),
                "cmd_line": ev.get("srcProcCmdLine", ev.get("processCmd", "")),
                "file_path": ev.get("filePath", ev.get("srcProcImagePath", "")),
                "sha256": ev.get("srcProcImageSha256", ev.get("fileSha256", "")),
                "user": ev.get("srcProcUser", ""),
                "parent_process": ev.get("parentProcessName",
                                          ev.get("srcProcParentName", "")),
                "site_name": ev.get("siteName", ""),
            })

        results.sort(key=lambda x: x.get("event_time", ""))
        return results

    # ─────────────────────────────────────────
    # Utility: Date Helpers
    # ─────────────────────────────────────────

    @staticmethod
    def to_iso(date_str: str, end_of_day: bool = False) -> Optional[str]:
        """Convert YYYY-MM-DD to ISO 8601 string."""
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            if end_of_day:
                dt = dt.replace(hour=23, minute=59, second=59)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            return None

    @staticmethod
    def relative_date(description: str) -> tuple:
        """
        Resolve natural language date to (start_iso, end_iso).
        Supports: 'today', 'yesterday', 'last 7 days', 'last 30 days',
                  'this week', 'last week', 'this month', 'last month',
                  'last N days', 'this year'
        """
        now = datetime.now(timezone.utc)
        desc = description.lower().strip()

        if desc == "today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return start.isoformat(), now.isoformat()

        if desc == "yesterday":
            yday = now - timedelta(days=1)
            start = yday.replace(hour=0, minute=0, second=0, microsecond=0)
            end = yday.replace(hour=23, minute=59, second=59)
            return start.isoformat(), end.isoformat()

        if desc in ("this week", "last 7 days"):
            start = now - timedelta(days=7)
            return start.isoformat(), now.isoformat()

        if desc == "last week":
            end = now - timedelta(days=now.weekday() + 1)
            start = end - timedelta(days=6)
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = end.replace(hour=23, minute=59, second=59)
            return start.isoformat(), end.isoformat()

        if desc in ("last 30 days", "this month"):
            start = now - timedelta(days=30)
            return start.isoformat(), now.isoformat()

        if desc == "last month":
            first_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            end = first_this_month - timedelta(seconds=1)
            start = end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            return start.isoformat(), end.isoformat()

        if desc in ("this year", "year-to-date", "ytd"):
            start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            return start.isoformat(), now.isoformat()

        if desc == "last quarter":
            start = now - timedelta(days=90)
            return start.isoformat(), now.isoformat()

        # "last N days"
        import re
        m = re.match(r"last (\d+) days?", desc)
        if m:
            days = int(m.group(1))
            start = now - timedelta(days=days)
            return start.isoformat(), now.isoformat()

        # Fallback: last 30 days
        start = now - timedelta(days=30)
        return start.isoformat(), now.isoformat()
