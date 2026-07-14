"""
Sentrium Integrated SOC Dashboard — Async Data Fetcher
High-performance async engine for SentinelOne + AlienVault APIs.
Uses httpx with connection pooling for maximum throughput.
"""

from __future__ import annotations
import asyncio
import json
import logging
import pathlib
import time
from datetime import datetime, timedelta, timezone
from collections import Counter
from typing import Optional

import httpx

from config import settings
from models import (
    DashboardState, ClientSummary, PlatformStatus,
    AlertItem, TimePoint, ThreatClassification,
    AVPriorityRow, AVStatusCount, AVMethodRow, AVAssetRow,
)

logger = logging.getLogger("soc_dashboard.fetcher")

# ════════════════════════════════════════════════════════════════
#  SentinelOne Async Fetcher
# ════════════════════════════════════════════════════════════════

class S1Fetcher:
    """Async SentinelOne API v2.1 client."""

    def __init__(self):
        self.base_url = settings.S1_BASE_URL.rstrip("/")
        self._client: Optional[httpx.AsyncClient] = None

    def _make_client(self) -> httpx.AsyncClient:
        """Always create a fresh client with up-to-date credentials."""
        return httpx.AsyncClient(
            headers={
                "Authorization": f"ApiToken {settings.S1_API_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=httpx.Timeout(45.0, connect=15.0),
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Return a healthy client, recreating if needed."""
        if self._client is None or self._client.is_closed:
            self._client = self._make_client()
        return self._client

    async def _reset_client(self):
        """Force-close and recreate the client."""
        if self._client and not self._client.is_closed:
            try:
                await self._client.aclose()
            except Exception:
                pass
        self._client = self._make_client()
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _paginate(self, endpoint: str, params: dict = None, max_items: int = 5000) -> list[dict]:
        """Fetch all pages from a cursor-paginated endpoint."""
        client = await self._get_client()
        if params is None:
            params = {}
        params = {**params, "limit": 200}
        all_items = []
        cursor = None

        _retry_budget = 3   # max 429 retries per page

        while True:
            if cursor:
                params["cursor"] = cursor

            try:
                resp = await client.get(f"{self.base_url}/{endpoint}", params=params)
                if resp.status_code == 401:
                    logger.error(f"S1 Auth failed on {endpoint} — token may be expired")
                    break

                # ── Rate-limit handling ──────────────────────────────────────
                if resp.status_code == 429:
                    if _retry_budget <= 0:
                        logger.warning(f"S1 {endpoint} 429 — retry budget exhausted, skipping")
                        break
                    wait = int(resp.headers.get("Retry-After", "2"))
                    wait = min(wait, 10)   # cap at 10 s
                    logger.debug(f"S1 {endpoint} 429 — sleeping {wait}s (budget={_retry_budget})")
                    await asyncio.sleep(wait)
                    _retry_budget -= 1
                    continue   # retry same page

                if resp.status_code != 200:
                    logger.warning(f"S1 {endpoint} returned {resp.status_code}")
                    break

                _retry_budget = 3  # reset on successful page
                body = resp.json()
                data = body.get("data", body)
                if isinstance(data, dict) and "sites" in data:
                    data = data["sites"]
                if isinstance(data, list):
                    all_items.extend(data)

                if len(all_items) >= max_items:
                    all_items = all_items[:max_items]
                    break

                pagination = body.get("pagination", {}) or {}
                cursor = pagination.get("nextCursor")
                if not cursor:
                    break

                await asyncio.sleep(0.05)

            except httpx.RequestError as e:
                logger.warning(f"S1 network error on {endpoint}: {e} — retrying with fresh client")
                client = await self._reset_client()
                try:
                    resp = await client.get(f"{self.base_url}/{endpoint}", params=params)
                    if resp.status_code == 200:
                        body = resp.json()
                        data = body.get("data", body)
                        if isinstance(data, dict) and "sites" in data:
                            data = data["sites"]
                        if isinstance(data, list):
                            all_items.extend(data)
                        pagination = body.get("pagination", {}) or {}
                        cursor = pagination.get("nextCursor")
                        if not cursor:
                            break
                    else:
                        logger.error(f"S1 retry failed on {endpoint}: {resp.status_code}")
                        break
                except Exception as retry_e:
                    logger.error(f"S1 retry error on {endpoint}: {retry_e}")
                    break

        return all_items

    async def discover_sites(self) -> list[dict]:
        """Auto-discover all sites (clients) from SentinelOne."""
        if not settings.s1_configured():
            return []
        try:
            sites = await self._paginate("sites")
            logger.info(f"S1: Discovered {len(sites)} sites")
            return sites
        except Exception as e:
            logger.error(f"S1 site discovery failed: {e}")
            return []

    async def fetch_agents(self, site_id: str) -> list[dict]:
        """Fetch all agents/endpoints for a site."""
        return await self._paginate("agents", {"siteIds": site_id, "limit": 1000})

    async def fetch_threats(self, site_id: str, days_back: int = 30) -> list[dict]:
        """Fetch threats for a site within the last N days."""
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        return await self._paginate("threats", {
            "siteIds": site_id,
            "createdAt__gte": start,
            "createdAt__lte": end,
            "sortBy": "createdAt",
            "sortOrder": "desc",
        })

    async def fetch_risks(self, site_id: str, days_back: int | None = None) -> list[dict]:
        """
        Fetch application vulnerability risks via /application-management/risks.
        Returns raw list of risk records — used to compute both vuln endpoints
        (unique endpoint names) and vuln app count (total records).
        Falls back to empty list if unavailable.
        """
        params = {
            "siteIds":   site_id,
            "sortBy":    "detectionDate",
            "sortOrder": "desc",
        }
        if days_back is not None:
            now = datetime.now(timezone.utc)
            params["detectionDate__gte"] = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            params["detectionDate__lte"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            return await self._paginate(
                "application-management/risks",
                params,
                max_items=200,   # 1 page max — prevents rate-limit cascade across 13 clients
            )
        except Exception as e:
            logger.debug(f"S1 application risks unavailable for site {site_id}: {e}")
            return []

    async def fetch_blocklisted_hashes(self, site_id: str) -> int:
        """
        Count blocklisted hash restrictions via /restrictions?type=black_hash.
        Counts only restrictions scoped to this site to avoid inherited account/group totals.
        Falls back to 0 if the endpoint is unavailable.
        Uses limit=1 and pagination.totalItems to avoid downloading all hashes.
        """
        client = await self._get_client()
        params = {
            "siteIds":         site_id,
            "type":            "black_hash",
            "includeParents":  "false",
            "includeChildren": "false",
            "limit":           1,
        }
        _retry_budget = 3
        while True:
            try:
                resp = await client.get(f"{self.base_url}/restrictions", params=params)
                if resp.status_code == 401:
                    logger.error("S1 Auth failed on restrictions — token may be expired")
                    return 0
                if resp.status_code == 429:
                    if _retry_budget <= 0:
                        logger.warning("S1 restrictions 429 — retry budget exhausted, skipping")
                        return 0
                    wait = int(resp.headers.get("Retry-After", "2"))
                    wait = min(wait, 10)
                    logger.debug(f"S1 restrictions 429 — sleeping {wait}s (budget={_retry_budget})")
                    await asyncio.sleep(wait)
                    _retry_budget -= 1
                    continue
                if resp.status_code != 200:
                    logger.warning(f"S1 restrictions returned {resp.status_code}")
                    return 0
                
                body = resp.json()
                pagination = body.get("pagination", {}) or {}
                if "totalItems" in pagination:
                    return int(pagination["totalItems"])
                data = body.get("data", [])
                return len(data)
            except Exception as e:
                logger.debug(f"S1 blocklisted hashes unavailable for site {site_id}: {e}")
                return 0


    async def fetch_alerts(self, site_id: str, days_back: int = 7) -> list[dict]:
        """Fetch cloud detection alerts for a site."""
        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        return await self._paginate("cloud-detection/alerts", {
            "siteIds": site_id,
            "createdAt__gte": start,
            "createdAt__lte": end,
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }, max_items=200)


# ════════════════════════════════════════════════════════════════
#  AlienVault Async Fetcher
# ════════════════════════════════════════════════════════════════

class AVFetcher:
    """Async AlienVault USM Anywhere API client (deployments-based)."""

    def __init__(self):
        self.subdomain = settings.AV_SUBDOMAIN
        self.base_url = f"https://{self.subdomain}"
        self._token: Optional[str] = None
        self._token_expiry: float = 0
        self._dep_tokens: dict = {}      # dep_url -> {token, expiry}
        self._deployments: list = []     # cached deployment list
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=False,
                # 15 s read timeout: prevents 5-min hang when AV auth
                # tries 5 OAuth endpoints each at the old 60 s limit.
                timeout=httpx.Timeout(15.0, connect=10.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _get_token_with_path(self) -> tuple[Optional[str], str]:
        """Get OAuth2 token + base API path (e.g. '/api/1.1') from the working endpoint."""
        if self._token and time.time() < self._token_expiry:
            return self._token, getattr(self, "_base_api_path", "/api/1.1")

        client = await self._get_client()
        base = self.base_url.rstrip("/")
        for ep in ("/api/1.1/oauth/token", "/api/1.0/oauth/token", "/api/2.0/oauth/token",
                   "/oauth/token", "/oauth2/token"):
            try:
                resp = await client.post(
                    base + ep,
                    data={"grant_type": "client_credentials"},
                    auth=(settings.AV_CLIENT_ID, settings.AV_CLIENT_SECRET),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._token = data.get("access_token")
                    self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
                    # Derive base path from the working endpoint
                    if "1.1" in ep:
                        self._base_api_path = "/api/1.1"
                    elif "2.0" in ep:
                        self._base_api_path = "/api/2.0"
                    else:
                        self._base_api_path = "/api/1.1"
                    logger.info(f"AV: Token acquired via {ep} (base_path={self._base_api_path})")
                    return self._token, self._base_api_path
                logger.warning(f"AV auth {ep} → HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"AV auth {ep} → {e}")
        logger.error("AV: All auth endpoints failed")
        return None, "/api/1.1"

    async def _get_token(self) -> Optional[str]:
        """Compatibility wrapper — returns just the token."""
        token, _ = await self._get_token_with_path()
        return token

    def _resolve_deployment_url(self, dep: dict) -> Optional[str]:
        """Extract a usable base URL from a deployment object."""
        # Try explicit URL fields first
        for key in ("url", "fqdn", "hostname", "base_url"):
            val = dep.get(key, "")
            if val:
                return (f"https://{val}" if not val.startswith("http") else val).rstrip("/")
        # Try self-link href
        self_link = dep.get("_links", {}).get("self", {}).get("href", "")
        if self_link and "alienvault.cloud" in self_link:
            from urllib.parse import urlparse as _up
            p = _up(self_link)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"
        # Try id field (sometimes contains full URL)
        dep_id = dep.get("id", "")
        if dep_id and "://" in dep_id:
            return f"https://{dep_id.split('://')[1].split('/')[0]}"
        # Try name field — with or without .alienvault.cloud suffix
        name = dep.get("name", "")
        if name:
            if "alienvault.cloud" in name:
                return (f"https://{name}" if not name.startswith("http") else name).rstrip("/")
            # Construct from bare name (e.g. 'capitalsage' → 'https://capitalsage.alienvault.cloud')
            if name and not name.startswith("http") and " " not in name:
                return f"https://{name}.alienvault.cloud"
        return None

    async def _get_deployment_token(self, dep_url: str) -> Optional[str]:
        """Authenticate against a specific deployment and cache the token."""
        cached = self._dep_tokens.get(dep_url)
        if cached and time.time() < cached["expiry"]:
            return cached["token"]
        client = await self._get_client()
        for ep in ("/api/2.0/oauth/token", "/api/1.1/oauth/token"):
            try:
                resp = await client.post(
                    dep_url.rstrip("/") + ep,
                    data={"grant_type": "client_credentials"},
                    auth=(settings.AV_CLIENT_ID, settings.AV_CLIENT_SECRET),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    token = data.get("access_token")
                    self._dep_tokens[dep_url] = {
                        "token": token,
                        "expiry": time.time() + int(data.get("expires_in", 3600)) - 300,
                    }
                    return token
            except Exception:
                continue
        return None

    async def fetch_deployments(self) -> list[dict]:
        """Fetch all deployments — exact async port of working extractor."""
        if not settings.av_configured():
            return []
        if self._deployments:
            return self._deployments
        token, base_api_path = await self._get_token_with_path()
        if not token:
            logger.warning("AV token failed — skipping AV deployments (no mock fallback)")
            return []

        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        base = self.base_url.rstrip("/")
        # Mirror working extractor: base_api_path first, then fallbacks, deduplicated
        paths_raw = [
            f"{base_api_path.rstrip('/')}/deployments",
            "/api/2.0/deployments",
            "/api/1.1/deployments",
            "/deployments",
        ]
        seen: set = set()
        paths = [p for p in paths_raw if not (p in seen or seen.add(p))]  # type: ignore
        for path in paths:
            try:
                resp = await client.get(base + path, headers=headers, timeout=30)
                logger.info(f"AV deployments {path} → HTTP {resp.status_code}")
                if resp.status_code == 200:
                    data = resp.json()
                    import json as _json
                    logger.info(f"AV deployments raw: {_json.dumps(data)[:600]}")
                    # Exact if/elif pattern from working extractor (avoids 'or' chaining bug)
                    if "_embedded" in data:
                        embedded = data["_embedded"]
                        # Try all possible key names
                        deps = (embedded.get("deployments")
                                or embedded.get("tenantList")
                                or embedded.get("tenants")
                                or next(iter(embedded.values()), []))
                    elif isinstance(data, list):
                        deps = data
                    else:
                        deps = data.get("deployments", [])
                    logger.info(f"AV: {len(deps)} deployment objects from {path}")
                    if deps:
                        logger.info(f"AV: keys={list(deps[0].keys())} | first={deps[0]}")
                        for d in deps:
                            d["_resolved_url"] = self._resolve_deployment_url(d)
                        valid = [d for d in deps if d.get("_resolved_url")]
                        logger.info(f"AV: {len(valid)}/{len(deps)} with resolved URLs")
                        # Return all (even without URLs) — alarm fetch skips unresolvable ones
                        self._deployments = deps
                        return deps
                    else:
                        logger.warning(f"AV: {path} returned 200 but 0 deployments")
            except Exception as e:
                logger.warning(f"AV deployments {path} → {e}")
        logger.warning("AV: No deployments — using central URL as fallback")
        return []


    async def _fetch_alarms_one(self, dep_url: str, dep_name: str, central_token: str, days_back: int) -> list[dict]:
        """Fetch alarms from one deployment with strict client-side time filtering."""
        if not dep_url:
            logger.warning(f"AV: {dep_name} has no URL — skipping")
            return []
        client = await self._get_client()
        token = (await self._get_deployment_token(dep_url)) or central_token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        now      = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(days=days_back)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        url = dep_url.rstrip("/") + "/api/2.0/alarms"

        # Match the Streamlit reference script: exclude suppressed alarms,
        # restrict to active statuses, use larger page size for accuracy.
        # IMPORTANT: pass status as a list so httpx sends repeated params
        # (status=open&status=closed&status=in_review) just like the requests
        # library does in the Streamlit extractor. A comma-joined string would
        # be URL-encoded and the AV API would return 0 results.
        params: dict = {
            "timestamp_received_gte": start_ms,
            "timestamp_received_lte": end_ms,
            "sort": "timestamp_received,desc",
            "suppressed": "false",
            "size": 500,
            "page": 0,
        }
        # Build params as a list of tuples so httpx sends repeated query params:
        # ?status=open&status=closed&status=in_review
        # This matches the requests library behavior in the Streamlit reference.
        base_params = list(params.items()) + [
            ("status", "open"),
            ("status", "closed"),
            ("status", "in_review"),
        ]
        all_alarms: list[dict] = []
        total_elements = None   # initialised here so it's always defined
        try:
            resp = await client.get(url, headers=headers, params=base_params, timeout=30)
            if resp.status_code != 200:
                logger.warning(f"AV alarms {dep_name} HTTP {resp.status_code} — retrying without status filter")
                # Fallback: retry without status filter (some deployments may not support it)
                fallback_params = [(k, v) for k, v in base_params if k != "status"]
                resp = await client.get(url, headers=headers, params=fallback_params, timeout=30)
                if resp.status_code != 200:
                    logger.warning(f"AV alarms {dep_name} fallback also failed: HTTP {resp.status_code}")
                    return []
            body = resp.json()

            # Log pagination metadata once so we can see the real structure
            page_meta = body.get("page", {})
            total_elements = page_meta.get("totalElements") or body.get("total_elements") or body.get("total")
            total_pages    = page_meta.get("totalPages")   or body.get("total_pages")   or body.get("totalPages")
            logger.info(f"AV: {dep_name} page_meta={page_meta} total_elements={total_elements} total_pages={total_pages}")

            batch = body.get("_embedded", {}).get("alarms", [])
            for a in batch:
                a["_deployment_name"] = dep_name
            all_alarms.extend(batch)

            # Pagination cap matching the Streamlit reference (max_records=20000):
            # - Large deployments (>1000 alarms): fetch up to 10 pages = 5000 alarms
            # - Small deployments: fetch up to 20 pages
            # This balances accuracy with fetch time across all deployments in parallel.
            large_dataset = total_elements and int(total_elements) > 1000
            max_pages = 10 if large_dataset else 20
            page_num = 1
            while batch and page_num < max_pages:
                try:
                    page_params = [(k, v) for k, v in base_params if k != "page"] + [("page", str(page_num))]
                    r = await client.get(url, headers=headers, params=page_params, timeout=30)
                    if r.status_code != 200:
                        break
                    rbody = r.json()
                    batch = rbody.get("_embedded", {}).get("alarms", [])
                    for a in batch:
                        a["_deployment_name"] = dep_name
                    all_alarms.extend(batch)
                    logger.debug(f"AV: {dep_name} page {page_num} -> {len(batch)} alarms")
                    page_num += 1
                except Exception as pe:
                    logger.warning(f"AV: {dep_name} page {page_num} error: {pe}")
                    break
        except Exception as e:
            logger.error(f"AV alarm fetch {dep_name}: {e}")

        # The API already filtered by timestamp_received_gte, no local filter needed
        filtered = all_alarms
        # Embed the true API total so _merge_av_data can show accurate counts even when
        # we stopped early due to the pagination cap.
        if filtered and total_elements:
            filtered[0]["_total_elements"] = int(total_elements)
        logger.info(
            f"AV: {dep_name} -> {len(all_alarms)} fetched (API total: {total_elements})"
        )
        return filtered

    async def fetch_alarms_per_deployment(self, days_back: int = 1) -> dict[str, list]:
        """
        Fetch alarms per deployment using each deployment's own /api/2.0/alarms endpoint.
        The central URL does NOT host alarms — only individual deployment URLs do.
        Uses the central OAuth token for all requests (works across all deployments).
        """
        logger.info(
            f"AV: fetch_alarms_per_deployment | base_url={self.base_url} | days_back={days_back}"
        )
        if not settings.av_configured():
            logger.warning("AV: not configured — skipping alarm fetch")
            return {}

        token = await self._get_token()
        if not token:
            logger.error("AV: central token failed — cannot fetch alarms")
            return {}

        deployments = await self.fetch_deployments()
        if not deployments:
            logger.warning("AV: no deployments found")
            return {}

        logger.info(f"AV: fetching alarms for {len(deployments)} deployments")

        now      = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(days=days_back)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        headers  = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Limit concurrency to 4 so we don't hammer the API
        sem = asyncio.Semaphore(4)

        async def _fetch_one(dep: dict) -> tuple[str, list]:
            dep_name = dep.get("name", "Unknown")
            dep_url  = dep.get("_resolved_url", "")
            if not dep_url:
                logger.warning(f"AV: {dep_name} — no resolved URL, skipping")
                return dep_name, []

            url = dep_url.rstrip("/") + "/api/2.0/alarms"
            base_params = [
                ("timestamp_received_gte", start_ms),
                ("timestamp_received_lte", end_ms),
                ("sort",       "timestamp_received,desc"),
                ("suppressed", "false"),
                ("size",       "500"),
                ("status",     "open"),
                ("status",     "closed"),
                ("status",     "in_review"),
            ]

            all_alarms: list[dict] = []
            total_elements: int | None = None
            http_client = await self._get_client()

            async with sem:
                for page_num in range(10):   # up to 10 pages × 500 = 5000 per deployment
                    page_params = base_params + [("page", str(page_num))]
                    try:
                        resp = await http_client.get(
                            url, headers=headers, params=page_params, timeout=30
                        )
                        if resp.status_code != 200:
                            if page_num == 0:
                                logger.warning(
                                    f"AV: {dep_name} HTTP {resp.status_code} — skipping"
                                )
                            break
                        body  = resp.json()
                        if page_num == 0:
                            pm = body.get("page", {})
                            total_elements = pm.get("totalElements")
                            logger.info(
                                f"AV: {dep_name} total={total_elements}"
                            )
                        batch = body.get("_embedded", {}).get("alarms", [])
                        if not batch:
                            break
                        for a in batch:
                            a["_deployment_name"] = dep_name
                        all_alarms.extend(batch)
                        if len(batch) < 500:   # last page
                            break
                    except Exception as exc:
                        if page_num == 0:
                            logger.error(f"AV alarm fetch {dep_name}: {exc}")
                        break

            if all_alarms and total_elements:
                all_alarms[0]["_total_elements"] = int(total_elements)
            logger.info(
                f"AV: {dep_name} → {len(all_alarms)} alarms "
                f"(API total: {total_elements})"
            )
            return dep_name, all_alarms

        results = await asyncio.gather(
            *[_fetch_one(d) for d in deployments],
            return_exceptions=True,
        )

        out: dict[str, list] = {}
        for res in results:
            if isinstance(res, tuple):
                name, alarms = res
                out[name] = alarms
            elif isinstance(res, Exception):
                logger.error(f"AV deployment gather error: {res}")

        logger.info(
            f"AV: {len(out)} deployments processed, "
            f"{sum(len(v) for v in out.values())} total alarms"
        )
        return out




    async def fetch_alarms(self, days_back: int = 30) -> list[dict]:
        """Flat alarm list (used by debug endpoint)."""
        all_alarms: list[dict] = []
        for alarms in (await self.fetch_alarms_per_deployment(days_back)).values():
            all_alarms.extend(alarms)
        return all_alarms

    async def fetch_events(self, days_back: int = 1) -> list[dict]:
        """Fetch events from central URL (summary use only)."""
        if not settings.av_configured():
            return []
        token = await self._get_token()
        if not token:
            return []
        client = await self._get_client()
        now = datetime.now(timezone.utc)
        start_ms = int((now - timedelta(days=days_back)).timestamp() * 1000)
        end_ms   = int(now.timestamp() * 1000)
        try:
            resp = await client.get(
                self.base_url.rstrip("/") + "/api/2.0/events",
                headers={"Authorization": f"Bearer {token}"},
                params={"timestamp_received_gte": start_ms, "timestamp_received_lte": end_ms,
                        "sort": "timestamp_received,desc", "size": 500, "page": 0},
            )
            if resp.status_code == 200:
                return resp.json().get("_embedded", {}).get("eventResources", [])
        except Exception as e:
            logger.warning(f"AV events: {e}")
        return []

    async def fetch_sensors(self) -> list[dict]:
        """Legacy compatibility — returns deployments for aggregator."""
        return await self.fetch_deployments()

    async def fetch_sensor_names(self) -> dict[str, str]:
        """
        Fetch real sensor list from AV and return a UUID→name mapping.
        Sensors are physical/cloud sensors (e.g. 'CybervergentAlienvault', 'usm-anywhere').
        """
        if not settings.av_configured():
            return {}
        token = await self._get_token()
        if not token:
            return {
                "sensor-Cybervergent-uuid": "Cybervergent-AV-Sensor",
                "sensor-3line Limited-uuid": "3line-AV-Sensor",
                "sensor-Fidelity Pension Managers-uuid": "Fidelity-AV-Sensor",
                "sensor-SunTrust Bank-uuid": "SunTrust-AV-Sensor",
                "sensor-Sentrium SIEM Gateway-uuid": "Sentrium-AV-Sensor"
            }
        client = await self._get_client()
        headers = {"Authorization": f"Bearer {token}"}
        base = self.base_url.rstrip("/")
        sensor_map: dict[str, str] = {}
        for path in ("/api/2.0/sensors", "/api/1.1/sensors", "/api/2.0/sensors/list"):
            try:
                resp = await client.get(base + path, headers=headers, timeout=20)
                if resp.status_code == 200:
                    data = resp.json()
                    sensors = (
                        data.get("_embedded", {}).get("sensors") or
                        data.get("_embedded", {}).get("sensor_instances") or
                        (data if isinstance(data, list) else [])
                    )
                    for s in sensors:
                        uid  = s.get("uuid") or s.get("id") or ""
                        name = s.get("name") or s.get("hostname") or uid
                        if uid:
                            sensor_map[uid] = name
                    logger.info(f"AV sensors: {len(sensor_map)} sensors from {path}")
                    if sensor_map:
                        break
            except Exception as e:
                logger.debug(f"AV sensors {path}: {e}")
        return sensor_map



# ════════════════════════════════════════════════════════════════
#  Dashboard Aggregator
# ════════════════════════════════════════════════════════════════

# Disk-cache path — sits next to fetcher.py in the project directory
_CACHE_FILE = pathlib.Path(__file__).parent / "dashboard_cache.json"

class DashboardAggregator:
    """
    Combines data from both platforms into a unified dashboard state.
    Runs as a background task, caching results in memory.
    Persists the last full state to disk so every restart shows instant data.
    """

    def __init__(self):
        self.s1 = S1Fetcher()
        self.av = AVFetcher()
        self._cache: Optional[DashboardState] = None
        self._lock = asyncio.Lock()
        self._running = False
        # Load the last persisted state immediately — users see full data on login
        self._load_from_disk()

    def _load_from_disk(self):
        """Load previously persisted DashboardState from disk.
        This makes clients appear instantly on every server restart/login,
        rather than waiting 30-90 s for the first live fetch to complete."""
        try:
            if _CACHE_FILE.exists():
                raw = _CACHE_FILE.read_text(encoding="utf-8")
                data = json.loads(raw)
                self._cache = DashboardState(**data)
                logger.info(
                    f"Disk cache loaded: {self._cache.total_clients} clients "
                    f"(last updated {self._cache.last_updated})"
                )
        except Exception as exc:
            logger.warning(f"Disk cache load skipped ({exc}) — will populate on first fetch")

    def _save_to_disk(self, state: DashboardState):
        """Persist current DashboardState to disk after each fetch cycle."""
        try:
            _CACHE_FILE.write_text(state.model_dump_json(), encoding="utf-8")
            logger.debug(f"Disk cache saved ({state.total_clients} clients)")
        except Exception as exc:
            logger.warning(f"Disk cache save failed (ignored): {exc}")

    @property
    def cached_state(self) -> Optional[DashboardState]:
        return self._cache

    async def close(self):
        await self.s1.close()
        await self.av.close()

    async def fetch_all(self) -> DashboardState:
        """
        Unified multi-client fetch:
        1. Discover ALL S1 sites + ALL AV sensors in parallel
        2. Fetch per-site S1 data + all AV alarms/events in parallel
        3. Unpack results / build S1 clients dict
        4. Fuzzy-merge AV deployments into S1 clients (or create AV-only cards)
        5. Build global KPIs
        """
        async with self._lock:
            t0 = time.time()
            logger.info("Starting data fetch cycle...")

            # Phase 1: Parallel discovery
            s1_sites, av_sensors = await asyncio.gather(
                self.s1.discover_sites(),
                self.av.fetch_sensors(),
                return_exceptions=True,
            )
            if isinstance(s1_sites, Exception):
                logger.error(f"S1 discovery error: {s1_sites}")
                s1_sites = []
            if isinstance(av_sensors, Exception):
                logger.warning(f"AV sensor discovery error: {av_sensors}")
                av_sensors = []

            # Retry S1 discovery if we got 0 sites (transient network blip at startup)
            if not s1_sites and settings.s1_configured():
                for _attempt in range(1, 3):   # 2 retries × 3s = 6s max delay
                    logger.warning(
                        f"S1 returned 0 sites — retrying in 3s (attempt {_attempt}/2)"
                    )
                    await asyncio.sleep(3)
                    try:
                        s1_sites = await self.s1.discover_sites()
                    except Exception as _re:
                        logger.error(f"S1 discovery retry {_attempt} error: {_re}")
                        s1_sites = []
                    if s1_sites:
                        logger.info(f"S1 discovery retry succeeded: {len(s1_sites)} sites")
                        break

            logger.info(f"Discovery: {len(s1_sites)} S1 sites, {len(av_sensors)} AV sensors")


            # ── Phase 2a: S1 per-site data + AV data in parallel ────────────
            # Launch the AV fetch as a background task NOW so it runs
            # concurrently with all the S1 per-site builds.  S1 typically
            # takes 30-90 s; AV takes 30-60 s.  By awaiting the AV task
            # AFTER S1 finishes, we get both datasets in one pass and can
            # seed the cache with fully merged data — no two-stage update.
            _av_alarm_task  = asyncio.create_task(
                self.av.fetch_alarms_per_deployment(days_back=1)
            )
            _av_sensor_task = asyncio.create_task(
                self.av.fetch_sensor_names()
            )
            _av_events_task = asyncio.create_task(
                self.av.fetch_events(days_back=1)
            )

            valid_s1_sites = [s for s in s1_sites if s.get("id")]
            s1_build_tasks = [
                self._build_s1_client(str(s["id"]), s.get("name", "Unknown"))
                for s in valid_s1_sites
            ]
            s1_results = await asyncio.gather(*s1_build_tasks, return_exceptions=True)

            # Build S1 clients dict
            clients: dict = {}
            for res in s1_results:
                if isinstance(res, Exception):
                    logger.error(f"S1 client build error: {res}")
                    continue
                if res is not None:
                    norm = _normalize_name(res.name)
                    clients[norm] = res
            logger.info(
                f"Phase 2a complete: {len(clients)} S1 clients built in "
                f"{time.time()-t0:.1f}s — awaiting AV task"
            )

            # ── Early cache seed ─────────────────────────────────────────────
            # Populate _cache with S1-only client data NOW so the dashboard
            # shows clients immediately rather than waiting for the full AV
            # merge to complete (which adds another 30-60 s).
            # The next few lines of code will overwrite _cache with the fully
            # merged result, so this is a transient optimistic update only.
            if clients:
                _now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                _partial_clients = list(clients.values())
                _partial = DashboardState(
                    last_updated=_now_str,
                    refresh_interval=settings.REFRESH_INTERVAL,
                    total_clients=len(_partial_clients),
                    global_endpoints=sum(
                        getattr(c, "total_endpoints", 0) or 0 for c in _partial_clients
                    ),
                    global_threats=sum(
                        getattr(c, "total_threats", 0) or 0 for c in _partial_clients
                    ),
                    clients=_partial_clients,
                )
                self._cache = _partial
                logger.info(
                    f"Early cache seed: {len(_partial_clients)} S1 clients — "
                    "broadcasting to connected WebSocket clients now"
                )
                # Immediately push S1 data to any already-connected browser tabs.
                # Lazy import avoids a circular dependency (ws_manager → fetcher → ws_manager).
                try:
                    from websocket_manager import ws_manager as _ws_mgr
                    asyncio.create_task(_ws_mgr.broadcast(_partial.model_dump()))
                except Exception as _ws_err:
                    logger.debug(f"Early seed WS broadcast skipped: {_ws_err}")

            # Await the AV tasks that were running concurrently
            # (they are likely already done; await is nearly instant)
            try:
                av_per_dep_raw = await _av_alarm_task
                if not isinstance(av_per_dep_raw, dict):
                    av_per_dep_raw = {}
            except Exception as _e:
                logger.error(f"AV alarms task error: {_e}")
                av_per_dep_raw = {}

            try:
                av_sensor_map = await _av_sensor_task
                if not isinstance(av_sensor_map, dict):
                    av_sensor_map = {}
            except Exception as _e:
                logger.warning(f"AV sensor names task error: {_e}")
                av_sensor_map = {}

            try:
                av_events_raw = await _av_events_task
                if not isinstance(av_events_raw, list):
                    av_events_raw = []
            except Exception as _e:
                logger.warning(f"AV events task error: {_e}")
                av_events_raw = []

            logger.info(
                f"AV data ready: {len(av_per_dep_raw)} deployments, "
                f"{sum(len(v) for v in av_per_dep_raw.values())} total alarms "
                f"at {time.time()-t0:.1f}s"
            )

            # ── Merge AV into S1 clients (Phase 5 moved up before seed) ──────
            # Do this BEFORE seeding so the first cache write includes full
            # merged data.  Users see complete S1+AV cards immediately.
            av_sensor_list = av_sensors if isinstance(av_sensors, list) else []
            for dep_name, alarms in av_per_dep_raw.items():
                if not isinstance(alarms, list):
                    alarms = []
                norm_dep = _normalize_name(dep_name)
                s1_match = _find_best_match(
                    norm_dep, list(clients.keys()), raw_av_name=dep_name
                )
                if s1_match:
                    _merge_av_data(
                        clients[s1_match], alarms, [], sensor_map=av_sensor_map
                    )
                    logger.info(
                        f"AV: '{dep_name}' merged -> S1 '{clients[s1_match].name}'"
                    )
                else:
                    clean_name = dep_name.replace("-", " ").title()
                    av_only = self._build_av_summary(
                        alarms, [], clean_name, sensor_map=av_sensor_map
                    )
                    clients[norm_dep] = av_only
                    logger.info(
                        f"AV: '{dep_name}' -> standalone AV-only card "
                        f"({len(alarms)} alarms)"
                    )

            # Add AV-only placeholder for deployments with no alarms this cycle
            # (DNS failures, etc.) so their cards still appear
            for dep in av_sensor_list:
                dep_name = dep.get("name", "") or dep.get("displayName", "") or ""
                if not dep_name:
                    continue
                norm_dep = _normalize_name(dep_name)
                if norm_dep in clients:
                    continue   # already present (merged or built above)
                if _find_best_match(
                    norm_dep, list(clients.keys()), raw_av_name=dep_name
                ):
                    continue   # will be merged — no standalone card needed
                display = (
                    dep.get("displayName") or dep_name
                ).replace("-", " ").title()
                clients[norm_dep] = ClientSummary(
                    name=display,
                    platforms=["AlienVault"],
                    threat_classifications=[],
                )
                logger.info(f"AV placeholder (no alarms): '{display}'")

            logger.info(
                f"Merge complete: {len(clients)} total clients at {time.time()-t0:.1f}s"
            )


            # (Phase 2b and Phase 5 are now consolidated above — AV ran
            #  concurrently with S1 and the merge happened before the seed)

            client_list = list(clients.values())

            # Phase 6: Global KPIs
            try:
                global_endpoints = sum(c.total_endpoints for c in client_list)
                global_threats   = sum(c.total_threats   for c in client_list)
                global_alerts    = sum(c.total_alerts    for c in client_list)
                global_events    = sum(c.events_processed for c in client_list)
                global_blocked   = sum(c.blocked_attempts for c in client_list)
                global_dfir      = sum(c.dfir_cases       for c in client_list)

                all_class_counts = Counter()
                for c in client_list:
                    for tc in c.threat_classifications:
                        all_class_counts[tc.name] += tc.count

                classification_colors = {
                    "Malware":     "#3B82F6", "Ransomware":  "#EF4444",
                    "Trojan":      "#F97316", "PUP":         "#22C55E",
                    "Cryptominer": "#8B5CF6", "Infostealer": "#EC4899",
                    "Packed":      "#F59E0B", "General":     "#6B7280",
                    "Malicious":   "#EF4444", "Suspicious":  "#F59E0B",
                }
                global_classifications = [
                    ThreatClassification(
                        name=name, count=count,
                        color=classification_colors.get(name, "#6B7280"),
                    )
                    for name, count in all_class_counts.most_common(10)
                ]

                combined_alerts = []
                for c in client_list:
                    combined_alerts.extend(c.recent_alerts)
                combined_alerts = sorted(combined_alerts, key=lambda a: a.time, reverse=True)[:20]

                global_timeline = self._build_global_timeline(client_list)
            except Exception as phase6_err:
                import traceback as _tb3
                logger.error(f"Phase 6 (KPI build) error — using zeros: {phase6_err}\n{_tb3.format_exc()}")
                global_endpoints = global_threats = global_alerts = 0
                global_events = global_blocked = global_dfir = 0
                global_classifications = []
                combined_alerts = []
                global_timeline = []

            status = "operational"
            if not settings.s1_configured() and not settings.av_configured():
                status = "unconfigured"
            elif not s1_sites and not av_per_dep_raw:
                status = "degraded"

            state = DashboardState(
                last_updated=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                refresh_interval=settings.REFRESH_INTERVAL,
                total_clients=len(client_list),
                system_status=status,
                global_endpoints=global_endpoints,
                global_threats=global_threats,
                global_alerts=global_alerts,
                global_events=global_events,
                global_blocked=global_blocked,
                global_dfir_cases=global_dfir,
                sectors_affected=len(client_list),
                clients=client_list,
                global_classifications=global_classifications,
                global_alerts_list=combined_alerts,
                global_timeline=global_timeline,
            )

            self._cache = state
            self._save_to_disk(state)   # persist full merged state for instant next-start
            elapsed = time.time() - t0
            logger.info(f"Fetch cycle complete: {len(client_list)} clients, {elapsed:.2f}s")
            return state


    async def _build_s1_client(self, site_id: str, site_name: str) -> ClientSummary:
        """Build client summary from SentinelOne data — 24h threat window."""
        agents, threats_24h, alerts_24h, risks, blocklisted_count = await asyncio.gather(
            self.s1.fetch_agents(site_id),
            self.s1.fetch_threats(site_id, days_back=1),      # 24 hours only
            self.s1.fetch_alerts(site_id, days_back=1),        # cloud detection alerts (24hr)
            self.s1.fetch_risks(site_id, days_back=1),         # app-mgmt risks detected in 24hr
            self.s1.fetch_blocklisted_hashes(site_id),         # blocklisted hash count
            return_exceptions=True,
        )

        if isinstance(agents, Exception):
            logger.warning(f"S1 agents error for {site_name}: {agents}")
            agents = []
        if isinstance(threats_24h, Exception):
            logger.warning(f"S1 threats error for {site_name}: {threats_24h}")
            threats_24h = []
        if isinstance(alerts_24h, Exception):
            logger.warning(f"S1 alerts error for {site_name}: {alerts_24h}")
            alerts_24h = []
        if isinstance(risks, Exception):
            logger.debug(f"S1 risks unavailable for {site_name}: {risks}")
            risks = []
        if isinstance(blocklisted_count, Exception):
            logger.debug(f"S1 blocklisted hashes unavailable for {site_name}: {blocklisted_count}")
            blocklisted_count = 0

        # ── Derive vuln counts from application-management/risks ──
        vuln_ep_set: set[str] = set()
        vuln_app_set: set[str] = set()
        for r in risks:
            ep = (r.get("endpointName") or r.get("endpoint")
                  or r.get("agentName")  or r.get("hostName") or "")
            if ep:
                vuln_ep_set.add(ep)
            app = (
                r.get("applicationName") or r.get("application")
                or r.get("appName") or r.get("name")
                or r.get("packageName") or r.get("softwareName") or ""
            )
            version = r.get("applicationVersion") or r.get("version") or ""
            if app:
                vuln_app_set.add(f"{app}|{version}")
        vuln_eps  = len(vuln_ep_set)   # unique endpoints with a risk record
        vuln_apps = len(vuln_app_set) or len(risks)

        logger.info(
            f"S1 [{site_name}]: {len(agents)} endpoints, {len(threats_24h)} threats (24h), "
            f"{len(alerts_24h)} alerts (24h), "
            f"{vuln_eps} vuln endpoints, {vuln_apps} vuln app risks, {blocklisted_count} blocklisted hashes"
        )


        # ── Threat classifications from 24h threats ──
        class_counter = Counter()
        for t in threats_24h:
            ti = t.get("threatInfo", {})
            confidence = ti.get("confidenceLevel", "").title()   # Malicious / Suspicious
            if confidence:
                class_counter[confidence] += 1

        classification_colors = {
            "Malicious":  "#EF4444",
            "Suspicious": "#F59E0B",
            "Malware":    "#3B82F6",
            "Ransomware": "#EF4444",
            "Trojan":     "#F97316",
            "PUP":        "#22C55E",
            "Cryptominer":"#8B5CF6",
            "General":    "#6B7280",
        }

        classifications = [
            ThreatClassification(
                name=name,
                count=count,
                color=classification_colors.get(name, "#6B7280"),
            )
            for name, count in class_counter.most_common(10)
        ]

        # ── Map analyst verdict to human-readable label ──
        VERDICT_MAP = {
            "true_positive":  "True Positive",
            "false_positive": "False Positive",
            "suspicious":     "Suspicious",
            "undefined":      "Undefined",
            "":               "Pending",
        }

        # ── Map incident status to human-readable label ──
        STATUS_MAP = {
            "unresolved": "Unresolved",
            "in_progress": "In Progress",
            "resolved":    "Resolved",
            "":            "Unknown",
        }

        # ── Build alerts table from 24h threats ──
        recent_alerts: list[AlertItem] = []
        for t in threats_24h:
            ti  = t.get("threatInfo", {})
            ari = t.get("agentRealtimeInfo", {})

            threat_name = (
                ti.get("threatName")
                or ti.get("filePath", "").split("\\")[-1].split("/")[-1]
                or "Unknown Threat"
            )

            # Use S1's native description fields (already human-readable)
            confidence_raw   = (ti.get("confidenceLevel", "") or "").lower()
            confidence_label = confidence_raw.title() if confidence_raw else "Unknown"
            severity         = "critical" if confidence_raw == "malicious" else "medium"

            verdict_label    = ti.get("analystVerdictDescription", "") or "Pending"
            status_label     = ti.get("incidentStatusDescription", "") or "Unknown"

            created  = ti.get("createdAt", "")
            endpoint = ari.get("agentComputerName", "")

            # Detecting engine
            engines = ti.get("engines", [])
            engine  = engines[0] if engines else ""

            recent_alerts.append(AlertItem(
                id=f"S1-{str(t.get('id', ''))[:6]}",
                alert_type=threat_name,
                source=endpoint,
                severity=severity,
                confidence=confidence_label,
                analyst_verdict=verdict_label,
                status=status_label,
                time=_format_relative_time(created),
                reported_at=_format_exact_time(created),
                platform="SentinelOne",
            ))

        seen_alert_ids = {a.id for a in recent_alerts if a.id}
        for alert in alerts_24h:
            ai = alert.get("alertInfo", {}) or {}
            ari = alert.get("agentRealtimeInfo", {}) or {}
            alert_id = str(alert.get("id") or ai.get("id") or ai.get("alertId") or "")
            display_id = f"S1A-{alert_id[:6]}" if alert_id else ""
            if display_id and display_id in seen_alert_ids:
                continue

            alert_name = (
                ai.get("alertName") or ai.get("name") or ai.get("ruleName")
                or alert.get("name") or alert.get("title") or "Cloud Detection Alert"
            )
            severity_raw = str(ai.get("severity") or alert.get("severity") or "").lower()
            confidence_raw = str(ai.get("confidenceLevel") or alert.get("confidenceLevel") or "").lower()
            confidence_label = confidence_raw.title() if confidence_raw else (severity_raw.title() if severity_raw else "Unknown")
            status_label = (
                ai.get("statusDescription") or ai.get("status")
                or alert.get("statusDescription") or alert.get("status") or "Unknown"
            )
            verdict_label = (
                ai.get("analystVerdictDescription") or ai.get("analystVerdict")
                or alert.get("analystVerdictDescription") or alert.get("analystVerdict") or "Pending"
            )
            created = ai.get("createdAt") or alert.get("createdAt") or ai.get("updatedAt") or alert.get("updatedAt") or ""
            endpoint = (
                ari.get("agentComputerName") or ai.get("agentName") or ai.get("computerName")
                or alert.get("agentName") or alert.get("computerName") or ""
            )

            recent_alerts.append(AlertItem(
                id=display_id,
                alert_type=alert_name,
                source=endpoint,
                severity=severity_raw or "medium",
                confidence=confidence_label,
                analyst_verdict=str(verdict_label).replace("_", " ").title(),
                status=str(status_label).replace("_", " ").title(),
                time=_format_relative_time(created),
                reported_at=_format_exact_time(created),
                platform="SentinelOne",
            ))

        # ── KPIs ──
        blocked = 0
        for t in threats_24h:
            m = str(t.get("threatInfo", {}).get("mitigationStatusDescription", "")).lower()
            if "mitigated" in m and "not" not in m:
                blocked += 1
        dfir = sum(
            1 for t in threats_24h
            if t.get("threatInfo", {}).get("incidentStatus", "") in ("unresolved", "in_progress")
        )

        timeline = _build_hourly_timeline(threats_24h)

        # ══════════════════════════════════════════════════════════════════
        # RICH S1 TELEMETRY — mirrors the Streamlit reporting tool
        # ══════════════════════════════════════════════════════════════════

        # ── Threat classifications (classification field) ──
        tc_counter: Counter = Counter()
        for t in threats_24h:
            ti = t.get("threatInfo", {})
            cls = ti.get("classification") or ti.get("confidenceLevel", "Unknown")
            if cls: tc_counter[cls.title()] += 1
        s1_threat_classifications = [{"label": k, "count": v} for k, v in tc_counter.most_common(15)]

        # ── Mitigation status ──
        mit_counter: Counter = Counter()
        for t in threats_24h:
            m = t.get("threatInfo", {}).get("mitigationStatusDescription") or "Unknown"
            mit_counter[m] += 1
        s1_threat_mitigations = [{"label": k, "count": v} for k, v in mit_counter.most_common(10)]

        # ── Top threat files ──
        file_counter: Counter = Counter()
        for t in threats_24h:
            ti = t.get("threatInfo", {})
            fname = (ti.get("threatName") or ti.get("displayName")
                     or (ti.get("filePath") or "").replace("\\", "/").split("/")[-1])
            if fname:
                file_counter[fname] += 1
        s1_threat_files = [{"label": k, "count": v} for k, v in file_counter.most_common(20)]

        # ── Detailed threat rows (for the threat table) ──
        s1_recent_threats_detail: list[dict] = []
        for t in threats_24h:
            ti  = t.get("threatInfo", {})
            ari = t.get("agentRealtimeInfo", {})
            fname = (ti.get("threatName") or ti.get("displayName")
                     or (ti.get("filePath") or "").replace("\\", "/").split("/")[-1] or "N/A")
            s1_recent_threats_detail.append({
                "endpoint":       ari.get("agentComputerName", "N/A"),
                "file":           fname,
                "classification": (ti.get("classification") or ti.get("confidenceLevel", "N/A")).title(),
                "mitigation":     ti.get("mitigationStatusDescription") or "N/A",
                "resolution":     ti.get("incidentStatusDescription")   or ti.get("incidentStatus", "N/A"),
                "verdict":        ti.get("analystVerdictDescription")   or "Pending",
                "reported_at":    _format_exact_time(ti.get("createdAt", "")),
                "agent_version":  ari.get("agentVersion", "N/A"),
            })

        # ── Vulnerability breakdowns (from risks) ──
        vuln_app_counter:  Counter = Counter()
        vuln_ep_counter:   Counter = Counter()
        vuln_sev_counter:  Counter = Counter()

        SEV_MAP = {
            "critical": "Critical", "high": "High",
            "medium": "Medium",     "low": "Low",
            "informational": "Informational", "info": "Informational",
            "none": "None", "unknown": "Unknown",
        }

        for r in risks:
            app = (r.get("applicationName") or r.get("application") or r.get("appName") or "")
            ver = (r.get("applicationVersion") or r.get("version") or "")
            if app:
                vuln_app_counter[f"{app} {ver}".strip()] += 1
            ep = (r.get("endpointName") or r.get("endpoint") or r.get("agentName") or "")
            if ep:
                vuln_ep_counter[ep] += 1
            raw_sev = str(r.get("severity") or "").lower()
            sev = SEV_MAP.get(raw_sev.split()[0] if raw_sev else "", "Unknown")
            if not sev or sev == "Unknown":
                score = r.get("nvdBaseScore") or r.get("baseScore") or r.get("riskScore")
                try:
                    s = float(score)
                    sev = "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low"
                except Exception:
                    sev = "Unknown"
            vuln_sev_counter[sev] += 1

        s1_vuln_apps      = [{"label": k, "count": v} for k, v in vuln_app_counter.most_common(30)]
        s1_vuln_endpoints = [{"label": k, "count": v} for k, v in vuln_ep_counter.most_common(20)]
        s1_vuln_severity  = [{"label": k, "count": v} for k, v in vuln_sev_counter.most_common()]

        # ── OS distribution + endpoint names (from agents) ──
        os_counter: Counter   = Counter()
        ver_counter: Counter  = Counter()
        ep_names: list[str]   = []
        attn_counter: Counter = Counter()

        for e in agents:
            cn = e.get("computerName")
            if cn: ep_names.append(cn)
            os_t = e.get("osType") or e.get("osName") or "Unknown"
            os_counter[os_t] += 1
            av = e.get("agentVersion")
            if av: ver_counter[av] += 1
            # Agent attention
            mp = e.get("missingPermissions")
            ua = e.get("userActionsNeeded") or ""
            op = e.get("operationalState") or ""
            if mp:                                attn_counter["Missing Permission"] += 1
            elif ua == "incompatible_os":         attn_counter["Incompatible OS"] += 1
            elif ua == "unprotected" or e.get("isProtected") is False:
                                                  attn_counter["Unprotected"] += 1
            elif op in ("shunned", "disabled"):   attn_counter["Agent Suppressed"] += 1
            elif ua and ua not in ("none",):      attn_counter["Attention Needed"] += 1

        s1_os_distribution  = [{"label": k, "count": v} for k, v in os_counter.most_common()]
        s1_agent_versions   = [{"label": k, "count": v} for k, v in ver_counter.most_common(20)]
        s1_agents_attention = [{"label": k, "count": v} for k, v in attn_counter.most_common()]

        return ClientSummary(
            name=site_name,
            platforms=["SentinelOne"],
            s1_site_id=site_id,
            total_endpoints=len(agents),
            total_threats=len(threats_24h),
            total_alerts=len(alerts_24h),
            s1_total_alerts=len(alerts_24h),
            s1_vulnerable_endpoints=vuln_eps,
            s1_vulnerable_apps=vuln_apps,
            s1_blocklisted_hashes=blocklisted_count,
            events_processed=len(agents) * 1000 + len(threats_24h) * 50,
            blocked_attempts=blocked,
            dfir_cases=dfir,
            threat_classifications=classifications,
            recent_alerts=recent_alerts[:50],
            event_timeline=timeline,
            # ── New rich telemetry ──
            s1_threat_classifications=s1_threat_classifications,
            s1_threat_mitigations=s1_threat_mitigations,
            s1_threat_files=s1_threat_files,
            s1_recent_threats=s1_recent_threats_detail[:50],
            s1_vuln_apps=s1_vuln_apps,
            s1_vuln_severity=s1_vuln_severity,
            s1_vuln_endpoints=s1_vuln_endpoints,
            s1_os_distribution=s1_os_distribution,
            s1_agent_versions=s1_agent_versions,
            s1_agents_attention=s1_agents_attention,
            s1_endpoint_names=ep_names,
            platform_data=[
                PlatformStatus(
                    platform="SentinelOne",
                    is_active=True,
                    total_endpoints=len(agents),
                    total_threats=len(threats_24h),
                    total_alerts=len(alerts_24h),
                    events_processed=len(agents) * 1000,
                    blocked_attempts=blocked,
                ),
            ],
        )



    def _build_av_summary(self, alarms: list[dict], events: list[dict],
                          name: str, sensor_map: dict | None = None) -> ClientSummary:
        """
        Build a standalone AV-only ClientSummary.
        Delegates all computation to _merge_av_data — AV-only cards
        are identical in richness to merged S1+AV cards.
        """
        intent_counter: Counter = Counter()
        for a in alarms:
            intent = a.get("rule_intent") or a.get("intent") or "Other"
            if intent:
                intent_counter[intent] += 1
        INTENT_COLORS = {
            "System Compromise":          "#DC2626",
            "Exploitation & Installation": "#EF4444",
            "Delivery & Attack":           "#F97316",
            "Reconnaissance & Probing":    "#F59E0B",
            "Environmental Awareness":     "#3B82F6",
        }
        classifications = [
            ThreatClassification(name=i, count=c, color=INTENT_COLORS.get(i, "#6B7280"))
            for i, c in intent_counter.most_common(5)
        ]
        summary = ClientSummary(
            name=name,
            platforms=[],
            threat_classifications=classifications,
            event_timeline=_build_hourly_timeline(alarms),
        )
        _merge_av_data(summary, alarms, events, sensor_map=sensor_map)
        return summary


    def _build_global_timeline(self, clients: list[ClientSummary]) -> list[TimePoint]:
        """Merge all client timelines into a global 24hr timeline."""
        # Create 24 hourly buckets
        now = datetime.now(timezone.utc)
        buckets: dict[str, dict] = {}
        for i in range(24):
            t = now - timedelta(hours=23 - i)
            key = t.strftime("%H:00")
            buckets[key] = {"value": 0, "blocked": 0}

        for c in clients:
            for tp in c.event_timeline:
                if tp.timestamp in buckets:
                    buckets[tp.timestamp]["value"] += tp.value
                    buckets[tp.timestamp]["blocked"] += tp.blocked

        return [
            TimePoint(timestamp=ts, value=d["value"], blocked=d["blocked"])
            for ts, d in buckets.items()
        ]


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

def _format_relative_time(iso_str: str) -> str:
    """Convert ISO datetime to relative time string."""
    if not iso_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - dt

        if delta.total_seconds() < 60:
            return "just now"
        elif delta.total_seconds() < 3600:
            mins = int(delta.total_seconds() / 60)
            return f"{mins} min ago"
        elif delta.total_seconds() < 86400:
            hours = int(delta.total_seconds() / 3600)
            return f"{hours}h ago"
        else:
            days = int(delta.total_seconds() / 86400)
            return f"{days}d ago"
    except Exception:
        return iso_str[:16] if len(iso_str) > 16 else iso_str


def _format_timestamp_ms(ts_ms) -> str:
    """Convert millisecond timestamp to relative time."""
    if not ts_ms:
        return "Unknown"
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
        return _format_relative_time(dt.isoformat())
    except Exception:
        return "Unknown"

def _format_exact_time(iso_str: str) -> str:
    """Format ISO timestamp as 'Apr 13th 2026 • 20:03' matching S1 UI."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        day = dt.day
        suffix = "th" if 11 <= day <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        month = dt.strftime("%b")
        return f"{month} {day}{suffix} {dt.year} • {dt.strftime('%H:%M')}"
    except Exception:
        return iso_str[:16] if len(iso_str) > 16 else iso_str

def _format_exact_time_ms(ts_ms) -> str:
    """Format millisecond epoch timestamp as 'Apr 13th 2026 • 20:03'."""
    if not ts_ms:
        return ""
    try:
        dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
        return _format_exact_time(dt.isoformat())
    except Exception:
        return ""


def _build_hourly_timeline(items: list[dict]) -> list[TimePoint]:
    """
    Build 24-hour timeline from SentinelOne threats OR AlienVault alarms.
    Supports both SentinelOne (threatInfo.createdAt ISO string)
    and AlienVault (timestamp_occured / timestamp_received epoch-ms) formats.
    """
    now = datetime.now(timezone.utc)
    buckets: dict[str, dict] = {}
    for i in range(24):
        t = now - timedelta(hours=23 - i)
        key = t.strftime("%H:00")
        buckets[key] = {"value": 0, "blocked": 0}

    for item in items:
        dt = None
        # ── SentinelOne format ────────────────────────────────────────
        ti = item.get("threatInfo", {})
        if ti:
            created = ti.get("createdAt", "")
            if created:
                try:
                    dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except Exception:
                    pass
        # ── AlienVault format (epoch-ms) ──────────────────────────────
        if dt is None:
            ts_ms = item.get("timestamp_occured") or item.get("timestamp_received")
            if ts_ms:
                try:
                    dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
                except Exception:
                    pass
        if dt is None:
            continue
        hour_key = dt.strftime("%H:00")
        if hour_key not in buckets:
            continue
        buckets[hour_key]["value"] += 1
        # Blocked: S1 mitigated threat OR AV critical/high priority
        if ti:
            mitigation = str(ti.get("mitigationStatusDescription", "")).lower()
            if "mitigated" in mitigation and "not" not in mitigation:
                buckets[hour_key]["blocked"] += 1
        else:
            prio = str(item.get("priority_label", "")).lower()
            st   = str(item.get("status", "")).lower()
            if prio in ("critical", "high") and st in ("closed", "resolved"):
                buckets[hour_key]["blocked"] += 1

    return [
        TimePoint(timestamp=ts, value=d["value"], blocked=d["blocked"])
        for ts, d in buckets.items()
    ]



# ════════════════════════════════════════════════════════════════
#  Multi-client AV helpers
# ════════════════════════════════════════════════════════════════

import re as _re

_SENSOR_STRIP_SUFFIXES = [
    " - usm sensor", " - usm", " - alienvault", " - sensor",
    " usm sensor", " usm", " sensor", " alienvault",
    "_sensor", "_usm", "-sensor", "-usm",
    " nfr", "-nfr", "_nfr",
    " primary", " secondary", " backup", " main",
    " hq", " head office", " headquarters",
]

def _sensor_to_client_name(sensor_name: str) -> str:
    """
    Derive a clean client name from an AV sensor name.
    E.g. "Acme Corp - USM Sensor 1"  →  "Acme Corp"
         "cybervergent-nfr-sensor"    →  "Cybervergent"
    """
    name = sensor_name.strip()
    lower = name.lower()
    for suffix in sorted(_SENSOR_STRIP_SUFFIXES, key=len, reverse=True):
        if lower.endswith(suffix):
            name  = name[: len(name) - len(suffix)].strip(" -_")
            lower = name.lower()
            break
    # Remove trailing numbers / separators
    name = _re.sub(r"[\s_\-]+\d+$", "", name).strip()
    # Title-case if all-caps or all-lower
    if name and (name == name.upper() or name == name.lower()):
        name = _re.sub(r"[-_]", " ", name).title()
    return name or sensor_name


_NORMALIZE_STOP = {
    "ltd", "limited", "inc", "plc", "ngo", "llc", "co", "corp",
    "nfr", "sensor", "usm", "alienvault", "sentinelone",
    "hq", "head", "office", "site", "primary", "secondary",
    "the", "and", "of",
}

def _normalize_name(name: str) -> str:
    """
    Normalize a client name for fuzzy matching.
    Lowercase, remove special chars, drop stopwords.
    """
    n = name.lower()
    n = _re.sub(r"[^a-z0-9\s]", " ", n)
    tokens = [t for t in n.split() if t and t not in _NORMALIZE_STOP and len(t) > 1]
    return " ".join(tokens)



# Explicit AV-name → S1-name mapping.
# Keys  : lowercase of EITHER the raw AV deployment name  (e.g. "9psb-com-ng2")
#          OR the cleaned sensor key from _sensor_to_client_name (e.g. "9 Psb Com Ng").
#          All keys are matched case-insensitively at runtime.
# Values: the normalized S1 candidate key (_normalize_name(s1_site_name)).
_AV_TO_S1_MAP = {
    # ── AppZone / Qore ────────────────────────────────────────────────────────
    "appzonegroup (qore)": "qore inc technologies",
    "appzonegroup":        "qore inc technologies",
    "appzone":             "qore inc technologies",
    "qore":                "qore inc technologies",
    "appzonegroup (qore) usm sensor": "qore inc technologies",
    # ── Zone Payment Network ──────────────────────────────────────────────────
    "zonenetwork":             "zone payment network",
    "zone network":            "zone payment network",
    "zone payment network":    "zone payment network",
    # ── eTranzact ─────────────────────────────────────────────────────────────
    "etranzact2":              "etranzact",
    "etranzact":               "etranzact",
    # ── Cybervergent (central + NFR sensor) ───────────────────────────────────
    "cybervergent":            "cybervergent",
    "cybervergent-nfr":        "cybervergent",
    "cybervergent nfr":        "cybervergent",
    "esentry-nfr":             "cybervergent",
    "esentry nfr":             "cybervergent",
    # ── 9PSB Payment Service Bank ─────────────────────────────────────────────
    # Raw deployment name and all cleaned sensor-key variants
    "9psb-com-ng2":            "9psb payment service bank",
    "9psb com ng2":            "9psb payment service bank",
    "9psb com ng":             "9psb payment service bank",
    "9 psb com ng":            "9psb payment service bank",
    "9psb":                    "9psb payment service bank",
    "9 psb":                   "9psb payment service bank",
}

def _find_best_match(norm_target: str, candidates: list, raw_av_name: str = "") -> Optional[str]:
    """
    Fuzzy-match norm_target against a list of normalized candidate keys.
    Priority: Explicit Map -> exact → substring → Jaccard word-overlap (≥ 30 % union).
    Returns the best matching key or None.
    """
    if not candidates:
        return None

    # 1. Check explicit mapping first
    raw_lower = raw_av_name.lower().strip()
    if raw_lower in _AV_TO_S1_MAP:
        mapped_s1 = _AV_TO_S1_MAP[raw_lower]
        # Find the normalized candidate that matches our mapped S1 name
        for key in candidates:
            if mapped_s1 in key or key in mapped_s1:
                return key

    if not norm_target:
        return None

    target_words = set(norm_target.split())
    best_key, best_score = None, 0.0

    for key in candidates:
        # 2. Exact
        if norm_target == key:
            return key
        # 3. Substring
        if norm_target in key or key in norm_target:
            score = len(norm_target) if norm_target in key else len(key)
            if score > best_score:
                best_score, best_key = float(score), key
            continue
        # 4. Word overlap (Jaccard)
        key_words = set(key.split())
        common = target_words & key_words
        if not common:
            continue
        union  = target_words | key_words
        score  = len(common) / len(union) * 100
        shorter = min(len(target_words), len(key_words))
        if shorter and len(common) / shorter >= 0.5:
            score += 20
        if score >= 30 and score > best_score:
            best_score, best_key = score, key

    return best_key


def _fallback_av_client_name() -> str:
    """Derive a human-readable fallback name from AV_SUBDOMAIN."""
    subdomain = settings.AV_SUBDOMAIN.split(".")[0]   # e.g. 'cybervergent-nfr'
    parts = [
        p for p in subdomain.split("-")
        if p.lower() not in ("nfr", "sensor", "usm", "av", "siem")
    ]
    return " ".join(p.title() for p in parts) or "AlienVault"


def _merge_av_data(client: ClientSummary, alarms: list, events: list,
                   sensor_map: dict[str, str] | None = None) -> None:
    """
    Enrich an existing (S1) ClientSummary with AlienVault alarm/event data.
    Computes: priority breakdown, top-5 methods/strategies/intents,
    sources, destinations, countries, sensor summary, 7-day trend,
    open/closed counts, resolution rate, labels.
    sensor_map: UUID → display name for actual AV sensor devices.
    """
    if "AlienVault" not in client.platforms:
        client.platforms.append("AlienVault")

    # ── Open / Closed / Resolution Rate ──────────────────────────
    # Use API-reported total if available (we may have fetched a subset due to pagination cap)
    api_total_elements = alarms[0].get("_total_elements", 0) if alarms else 0
    total_alarms = api_total_elements if api_total_elements > len(alarms) else len(alarms)
    open_count   = sum(1 for a in alarms if str(a.get("status","")).lower() == "open")
    closed_count = sum(1 for a in alarms if str(a.get("status","")).lower() in ("closed","resolved"))
    suppressed   = sum(1 for a in alarms if str(a.get("status","")).lower() in ("suppressed","auto_closed","autoclosed"))
    # Scale open/closed to the API total if we only have a sample
    if api_total_elements > len(alarms) and len(alarms) > 0:
        scale = api_total_elements / len(alarms)
        open_count   = round(open_count   * scale)
        closed_count = round(closed_count * scale)
        suppressed   = round(suppressed   * scale)
    resolution_rate = round((closed_count / total_alarms * 100), 1) if total_alarms else 0.0

    # ── Priority x Status breakdown ──────────────────────────────
    PRIORITY_COLORS = {
        "critical": "#DC2626", "high": "#EF4444",
        "medium": "#F59E0B",   "low": "#22C55E",
    }
    prio_map: dict[str, dict] = {}
    for a in alarms:
        prio = str(a.get("priority_label", "low")).lower()
        if prio not in ("critical", "high", "medium", "low"):
            prio = "low"
        st = str(a.get("status", "")).lower()
        if prio not in prio_map:
            prio_map[prio] = {"open": 0, "closed": 0, "in_review": 0, "other": 0}
        if st == "open":
            prio_map[prio]["open"] += 1
        elif st in ("closed", "resolved"):
            prio_map[prio]["closed"] += 1
        elif st in ("in_review", "investigating"):
            prio_map[prio]["in_review"] += 1
        else:
            prio_map[prio]["other"] += 1

    av_priority_breakdown = []
    sev_map = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for prio in ("critical", "high", "medium", "low"):
        if prio in prio_map:
            counts = prio_map[prio]
            total = sum(counts.values())
            sev_map[prio] = total
            av_priority_breakdown.append(AVPriorityRow(
                priority=prio.capitalize(),
                total=total,
                statuses=AVStatusCount(
                    open=counts["open"],
                    closed=counts["closed"],
                    in_review=counts["in_review"],
                    other=counts["other"],
                ),
                color=PRIORITY_COLORS.get(prio, "#6B7280"),
            ))

    # ── Method / Strategy / Intent — separate Top 5 ──────────────
    method_counter:   dict[str, int] = {}
    strategy_counter: dict[str, int] = {}
    intent_counter:   dict[str, int] = {}
    method_meta:      dict[str, dict] = {}

    for a in alarms:
        method   = ((a.get("rule_method")   or a.get("method")   or "Unknown").strip()) or "Unknown"
        strategy = (a.get("rule_strategy")  or a.get("strategy") or "").strip()
        intent   = (a.get("rule_intent")    or a.get("intent")   or "").strip()
        method_counter[method] = method_counter.get(method, 0) + 1
        if method not in method_meta:
            method_meta[method] = {"intent": intent, "strategy": strategy}
        if strategy:
            strategy_counter[strategy] = strategy_counter.get(strategy, 0) + 1
        if intent:
            intent_counter[intent] = intent_counter.get(intent, 0) + 1

    av_method_summary = [
        AVMethodRow(method=m, intent=method_meta[m]["intent"],
                    strategy=method_meta[m]["strategy"], count=c)
        for m, c in sorted(method_counter.items(), key=lambda x: -x[1])
    ][:5]
    av_top_strategies = [
        AVMethodRow(method=s, count=c)
        for s, c in sorted(strategy_counter.items(), key=lambda x: -x[1])
    ][:5]
    av_top_intents = [
        AVMethodRow(method=i, count=c)
        for i, c in sorted(intent_counter.items(), key=lambda x: -x[1])
    ][:5]

    # ── Top 5 Sources ─────────────────────────────────────────────
    source_counter: dict[str, Counter] = {}
    for a in alarms:
        src = a.get("source_name", "") or a.get("src_ip", "") or ""
        if not src:
            continue
        m = a.get("rule_method", "Unknown")
        if src not in source_counter:
            source_counter[src] = Counter()
        source_counter[src][m] += 1
    av_top_sources = [
        AVAssetRow(asset=s, count=sum(c.values()), alarm_types=list(dict(c.most_common(3)).keys()))
        for s, c in sorted(source_counter.items(), key=lambda x: -sum(x[1].values()))
    ][:5]

    # ── Top 5 Destinations ────────────────────────────────────────
    dest_counter: dict[str, Counter] = {}
    for a in alarms:
        dst = a.get("destination_name", "") or a.get("dst_ip", "") or ""
        if not dst:
            continue
        m = a.get("rule_method", "Unknown")
        if dst not in dest_counter:
            dest_counter[dst] = Counter()
        dest_counter[dst][m] += 1
    av_top_destinations = [
        AVAssetRow(asset=d, count=sum(c.values()), alarm_types=list(dict(c.most_common(3)).keys()))
        for d, c in sorted(dest_counter.items(), key=lambda x: -sum(x[1].values()))
    ][:5]

    # ── Top 5 Source Countries ────────────────────────────────────
    country_counter: dict[str, int] = {}
    for a in alarms:
        src_geo = a.get("src_geo") or {}
        country = (
            a.get("geo_country") or
            a.get("source_country") or
            (src_geo.get("country_name") if isinstance(src_geo, dict) else "") or ""
        )
        if country and country.strip():
            k = country.strip()
            country_counter[k] = country_counter.get(k, 0) + 1
    av_top_countries = [
        AVAssetRow(asset=c, count=n)
        for c, n in sorted(country_counter.items(), key=lambda x: -x[1])
    ][:5]

    # -- Per-Sensor Alarm Summary --------------------------------------
    # AV alarms carry sensor_name as a plain string (USMA-Sensor, xpresspayment etc)
    sensor_counter: dict[str, int] = {}
    _sm = sensor_map or {}
    if alarms:
        logger.debug(f"AV sensor fields: sensor_name={alarms[0].get('sensor_name')} "
                     f"sensors={alarms[0].get('sensors')} source_sensor={alarms[0].get('source_sensor')}")
    for a in alarms:
        # 1. Plain string - what AV UI Sensors filter shows
        name = a.get("sensor_name") or a.get("source_sensor") or ""
        if not name:
            # 2. UUID list resolved via sensor_map
            raw_sensors = a.get("sensors") or []
            if isinstance(raw_sensors, list) and raw_sensors:
                name = _sm.get(str(raw_sensors[0]), str(raw_sensors[0]))
        if not name:
            # 3. Single UUID field
            uid = str(a.get("sensor_uuid", ""))
            name = _sm.get(uid, uid) if uid else ""
        if not name:
            # 4. Deployment name as last resort
            name = a.get("_deployment_name", "Unknown")
        sensor_counter[name] = sensor_counter.get(name, 0) + 1
    av_sensor_summary = [
        AVAssetRow(asset=s, count=n)
        for s, n in sorted(sensor_counter.items(), key=lambda x: -x[1])
    ]
    # ── Label Tracking ────────────────────────────────────────────
    # AV alarms carry labels like 'Closed', 'False Positive', 'No Value'
    label_counter: dict[str, int] = {}
    for a in alarms:
        labels = a.get("labels") or []
        if isinstance(labels, list):
            for lbl in labels:
                lname = (lbl.get("name") if isinstance(lbl, dict) else str(lbl)).strip()
                if lname:
                    label_counter[lname] = label_counter.get(lname, 0) + 1
        elif isinstance(labels, str) and labels:
            label_counter[labels] = label_counter.get(labels, 0) + 1
        # If no labels field, count unlabelled
        if not labels:
            label_counter["No Label"] = label_counter.get("No Label", 0) + 1

    # ── 7-Day Daily Alarm Trend ───────────────────────────────────
    now_ts = datetime.now(timezone.utc)
    daily: dict[int, int] = {i: 0 for i in range(7)}
    for a in alarms:
        ts_ms = a.get("timestamp_occured") or a.get("timestamp_received") or 0
        try:
            alarm_dt = datetime.fromtimestamp(int(ts_ms) / 1000, tz=timezone.utc)
            days_ago = (now_ts.date() - alarm_dt.date()).days
            if 0 <= days_ago <= 6:
                daily[days_ago] += 1
        except Exception:
            pass
    av_daily_trend = [daily[i] for i in range(6, -1, -1)]  # oldest → today

    # ── AV AlertItems (up to 50) ──────────────────────────────────
    for a in alarms[:50]:
        prio_label = str(a.get("priority_label", "low")).lower()
        if prio_label not in ("critical", "high", "medium", "low"):
            prio_label = "low"
        ts_ms = a.get("timestamp_occured") or a.get("timestamp_received")
        st = str(a.get("status", "")).lower()
        client.recent_alerts.append(AlertItem(
            id=f"AV-{str(a.get('uuid', ''))[:6]}",
            alert_type=a.get("rule_method", a.get("rule_intent", "Alarm")),
            source=a.get("source_name", a.get("sensor", "")),
            destination=a.get("destination_name", ""),
            severity=prio_label,
            confidence=prio_label.capitalize(),
            status="Open" if st == "open" else
                   "In Review" if st in ("in_review", "investigating") else "Closed",
            time=_format_timestamp_ms(ts_ms),
            reported_at=_format_exact_time_ms(ts_ms),
            intent=a.get("rule_intent", ""),
            strategy=a.get("rule_strategy", ""),
            platform="AlienVault",
        ))

    # ── Set all fields on client ──────────────────────────────────
    client.av_total_alarms       = total_alarms
    client.av_open_alarms        = open_count
    client.av_closed_alarms      = closed_count
    client.av_resolution_rate    = resolution_rate
    client.av_suppressed         = suppressed
    client.av_priority_breakdown = av_priority_breakdown
    client.av_method_summary     = av_method_summary
    client.av_top_strategies     = av_top_strategies
    client.av_top_intents        = av_top_intents
    client.av_top_sources        = av_top_sources
    client.av_top_destinations   = av_top_destinations
    client.av_top_countries      = av_top_countries
    client.av_sensor_summary     = av_sensor_summary
    client.av_daily_trend        = av_daily_trend
    client.av_labels             = label_counter
    client.total_alerts         += total_alarms
    client.total_threats        += sev_map["critical"] + sev_map["high"]
    client.events_processed     += len(events)
    client.blocked_attempts     += sev_map["critical"]

    client.platform_data.append(PlatformStatus(
        platform="AlienVault",
        is_active=True,
        total_endpoints=0,
        total_threats=sev_map["critical"] + sev_map["high"],
        total_alerts=total_alarms,
        events_processed=len(events),
        blocked_attempts=sev_map["critical"],
    ))


def _generate_mock_av_alarms(client_name: str) -> list[dict]:
    import random
    from datetime import datetime, timedelta
    
    # Simple deterministic hash seed based on client_name
    seed_val = sum(ord(c) for c in client_name)
    random.seed(seed_val)
    
    methods = [
        ("Brute Force Attack Detected", "Brute Force", "Delivery & Attack"),
        ("Malicious Binary Execution", "Malware Execution", "System Compromise"),
        ("Phishing Link Clicked", "Phishing", "Delivery & Attack"),
        ("Unauthorized Data Transfer", "Exfiltration", "Exploitation & Installation"),
        ("SQL Injection Attempt", "Web Attack", "Delivery & Attack"),
        ("Suspicious PowerShell Script Execution", "Command Execution", "Exploitation & Installation"),
        ("Ransomware Behavior Blocked", "Ransomware", "System Compromise"),
        ("Port Scan Detected", "Reconnaissance", "Reconnaissance & Probing"),
        ("Internal C2 Connection Attempt", "Command & Control", "System Compromise")
    ]
    
    sources = ["Workstation-04", "External-IP-81", "Server-Prod-01", "Laptop-Analyst", "192.168.1.15", "10.0.4.52"]
    destinations = ["Domain Controller", "Database Server", "Firewall Gateway", "File Server", "10.0.12.5"]
    countries = ["US", "NG", "GB", "DE", "CN", "ZA", "IN"]
    priorities = ["critical", "high", "medium", "low"]
    statuses = ["open", "closed", "in_review"]
    
    alarms = []
    # Generate 15-35 alarms
    num_alarms = random.randint(15, 35)
    now = datetime.now()
    
    for i in range(num_alarms):
        method, strategy, intent = random.choice(methods)
        prio = random.choice(priorities)
        status = random.choice(statuses)
        src = random.choice(sources)
        dst = random.choice(destinations)
        country = random.choice(countries)
        
        # timestamp in the last 24 hours
        time_offset = random.randint(0, 24 * 60) # minutes
        dt = now - timedelta(minutes=time_offset)
        ts = int(dt.timestamp() * 1000)
        
        alarms.append({
            "uuid": f"mock-alarm-{client_name}-{i}",
            "priority_label": prio,
            "status": status,
            "rule_method": method,
            "rule_strategy": strategy,
            "rule_intent": intent,
            "source_name": src,
            "destination_name": dst,
            "country": country,
            "sensor_name": f"{client_name}-AV-Sensor",
            "sensor_uuid": f"sensor-{client_name}-uuid",
            "timestamp_received": ts,
            "timestamp_occured": ts,
        })
        
    return alarms


# Singleton
aggregator = DashboardAggregator()
