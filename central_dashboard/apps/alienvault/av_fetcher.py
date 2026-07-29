"""
AlienVault USM Anywhere — Async Fetcher
========================================
EXACT copy of the SOC dashboard AVFetcher class (soc_dashboard/fetcher.py).
Same tech stack: httpx.AsyncClient(verify=False), asyncio.gather, semaphore concurrency.

This is the proven-working implementation. Do NOT change the core fetch logic.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx

logger = logging.getLogger("alienvault.av_fetcher")

# ─── Settings (mirrors soc_dashboard/config.py) ──────────────────────────────

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default).strip().strip('"').strip("'")

def _get_subdomain() -> str:
    val = _env("AV_SUBDOMAIN", "cybervergent-central.alienvault.cloud")
    return val.replace("https://", "").replace("http://", "").rstrip("/")

def _get_client_id()     -> str: return _env("AV_CLIENT_ID")
def _get_client_secret() -> str: return _env("AV_CLIENT_SECRET")
def _av_configured()     -> bool: return bool(_get_client_id() and _get_client_secret())


# ─── AVFetcher — identical to SOC dashboard ──────────────────────────────────

class AVFetcher:
    """
    Async AlienVault USM Anywhere API client.
    Identical tech stack to soc_dashboard/fetcher.py AVFetcher.
    """

    def __init__(self):
        self._base_url      = f"https://{_get_subdomain()}"
        self._token:         Optional[str] = None
        self._token_expiry:  float = 0.0
        self._base_api_path: str   = "/api/1.1"
        self._dep_tokens:    dict  = {}   # dep_url → {token, expiry}
        self._deployments:   list  = []   # cached
        self._client:        Optional[httpx.AsyncClient] = None

    # ── HTTP client ───────────────────────────────────────────────────────────

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                verify=False,
                timeout=httpx.Timeout(60.0, connect=15.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=5),
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ── Authentication ────────────────────────────────────────────────────────

    async def _get_token_with_path(self) -> tuple[Optional[str], str]:
        """Get OAuth2 token + base API path from the working endpoint."""
        if self._token and time.time() < self._token_expiry:
            return self._token, self._base_api_path

        client = await self._get_client()
        base   = self._base_url.rstrip("/")

        for ep in (
            "/api/1.1/oauth/token",
            "/api/1.0/oauth/token",
            "/api/2.0/oauth/token",
            "/oauth/token",
            "/oauth2/token",
        ):
            try:
                resp = await client.post(
                    base + ep,
                    data={"grant_type": "client_credentials"},
                    auth=(_get_client_id(), _get_client_secret()),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._token = data.get("access_token")
                    self._token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
                    if "1.1" in ep:
                        self._base_api_path = "/api/1.1"
                    elif "2.0" in ep:
                        self._base_api_path = "/api/2.0"
                    else:
                        self._base_api_path = "/api/1.1"
                    logger.info(f"AV: token acquired via {ep} (base_path={self._base_api_path})")
                    return self._token, self._base_api_path
                logger.warning(f"AV auth {ep} → HTTP {resp.status_code}")
            except Exception as e:
                logger.warning(f"AV auth {ep} → {e}")

        logger.error("AV: all auth endpoints failed")
        return None, "/api/1.1"

    async def _get_token(self) -> Optional[str]:
        token, _ = await self._get_token_with_path()
        return token

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
                    auth=(_get_client_id(), _get_client_secret()),
                )
                if resp.status_code == 200:
                    data  = resp.json()
                    token = data.get("access_token")
                    self._dep_tokens[dep_url] = {
                        "token":  token,
                        "expiry": time.time() + int(data.get("expires_in", 3600)) - 300,
                    }
                    return token
            except Exception:
                continue
        return None

    # ── Deployment URL resolution ─────────────────────────────────────────────

    def _resolve_deployment_url(self, dep: dict) -> Optional[str]:
        """Extract a usable base URL from a deployment object. Same as SOC fetcher."""
        for key in ("url", "fqdn", "hostname", "base_url"):
            val = dep.get(key, "")
            if val:
                return (f"https://{val}" if not val.startswith("http") else val).rstrip("/")

        self_link = dep.get("_links", {}).get("self", {}).get("href", "")
        if self_link and "alienvault.cloud" in self_link:
            from urllib.parse import urlparse as _up
            p = _up(self_link)
            if p.scheme and p.netloc:
                return f"{p.scheme}://{p.netloc}"

        dep_id = dep.get("id", "")
        if dep_id and "://" in dep_id:
            host = dep_id.split("://")[1].split("/")[0]
            if host:
                return f"https://{host}"

        name = dep.get("name", "").strip()
        if name:
            if "alienvault.cloud" in name:
                return (f"https://{name}" if not name.startswith("http") else name).rstrip("/")
            if " " not in name and not name.startswith("http"):
                return f"https://{name}.alienvault.cloud"

        return None

    # ── Deployments ───────────────────────────────────────────────────────────

    async def fetch_deployments(self) -> list[dict]:
        """Fetch all deployments. Exact async port of working SOC fetcher."""
        if not _av_configured():
            return []
        if self._deployments:
            return self._deployments

        token, base_api_path = await self._get_token_with_path()
        if not token:
            logger.warning("AV: token failed — skipping deployments")
            return []

        client  = await self._get_client()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        base    = self._base_url.rstrip("/")

        paths_raw = [
            f"{base_api_path.rstrip('/')}/deployments",
            "/api/2.0/deployments",
            "/api/1.1/deployments",
            "/deployments",
        ]
        seen:  set  = set()
        paths: list = [p for p in paths_raw if not (p in seen or seen.add(p))]  # type: ignore

        for path in paths:
            try:
                resp = await client.get(base + path, headers=headers, timeout=30)
                logger.info(f"AV deployments {path} → HTTP {resp.status_code}")
                if resp.status_code != 200:
                    continue

                data = resp.json()
                logger.info(f"AV deployments raw (first 600): {str(data)[:600]}")

                if "_embedded" in data:
                    emb  = data["_embedded"]
                    deps = (
                        emb.get("deployments")
                        or emb.get("tenantList")
                        or emb.get("tenants")
                        or next(iter(emb.values()), [])
                    )
                elif isinstance(data, list):
                    deps = data
                else:
                    deps = data.get("deployments", [])

                logger.info(f"AV: {len(deps)} deployments from {path}")
                if not deps:
                    continue

                logger.info(f"AV: first dep keys={list(deps[0].keys())}")
                for d in deps:
                    d["_resolved_url"] = self._resolve_deployment_url(d)

                valid = [d for d in deps if d.get("_resolved_url")]
                logger.info(f"AV: {len(valid)}/{len(deps)} with resolved URLs")

                self._deployments = deps
                return deps

            except Exception as e:
                logger.warning(f"AV deployments {path} → {e}")

        logger.warning("AV: no deployments found")
        return []

    # ── Alarm fetch (single deployment) ──────────────────────────────────────

    async def _fetch_alarms_one(
        self,
        dep_url: str,
        dep_name: str,
        central_token: str,
        start_ms: int,
        end_ms: int,
    ) -> list[dict]:
        """
        Fetch alarms from ONE deployment.
        EXACT logic from SOC dashboard _fetch_alarms_one.
        """
        if not dep_url:
            logger.warning(f"AV: {dep_name} has no URL — skipping")
            return []

        client = await self._get_client()
        token  = (await self._get_deployment_token(dep_url)) or central_token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url     = dep_url.rstrip("/") + "/api/2.0/alarms"

        # EXACT params from SOC dashboard — status as list-of-tuples is critical
        params: dict = {
            "timestamp_received_gte": start_ms,
            "timestamp_received_lte": end_ms,
            "sort":       "timestamp_received,desc",
            "suppressed": "false",
            "size":       500,
            "page":       0,
        }
        base_params = list(params.items()) + [
            ("status", "open"),
            ("status", "closed"),
            ("status", "in_review"),
        ]

        all_alarms: list[dict] = []
        total_elements = None

        try:
            resp = await client.get(url, headers=headers, params=base_params, timeout=30)
            if resp.status_code != 200:
                logger.warning(f"AV alarms {dep_name} HTTP {resp.status_code} — retrying without status filter")
                fallback_params = [(k, v) for k, v in base_params if k != "status"]
                resp = await client.get(url, headers=headers, params=fallback_params, timeout=30)
                if resp.status_code != 200:
                    logger.warning(f"AV alarms {dep_name} fallback also failed: HTTP {resp.status_code}")
                    return []
                base_params = fallback_params

            body = resp.json()
            page_meta      = body.get("page", {})
            total_elements = page_meta.get("totalElements") or body.get("total_elements") or body.get("total")
            total_pages    = page_meta.get("totalPages")   or body.get("total_pages")    or body.get("totalPages")
            logger.info(f"AV: {dep_name} page_meta={page_meta} total={total_elements} pages={total_pages}")

            batch = body.get("_embedded", {}).get("alarms", [])
            for a in batch:
                a["_deployment_name"] = dep_name
            all_alarms.extend(batch)

            # Pagination cap (same as SOC dashboard)
            large_dataset = total_elements and int(total_elements) > 1000
            max_pages = 10 if large_dataset else 20
            page_num  = 1
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
                    logger.debug(f"AV: {dep_name} page {page_num} → {len(batch)} alarms")
                    page_num += 1
                except Exception as pe:
                    logger.warning(f"AV: {dep_name} page {page_num} error: {pe}")
                    break

        except Exception as e:
            logger.error(f"AV alarm fetch {dep_name}: {e}")

        if all_alarms and total_elements:
            all_alarms[0]["_total_elements"] = int(total_elements)
        logger.info(f"AV: {dep_name} → {len(all_alarms)} alarms (API total: {total_elements})")
        return all_alarms

    # ── Event fetch (single deployment) ───────────────────────────────────────

    async def _fetch_events_one(
        self,
        dep_url: str,
        dep_name: str,
        central_token: str,
        start_ms: int,
        end_ms: int,
    ) -> list[dict]:
        """Fetch events from ONE deployment."""
        if not dep_url:
            return []

        client  = await self._get_client()
        token   = (await self._get_deployment_token(dep_url)) or central_token
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url     = dep_url.rstrip("/") + "/api/2.0/events"

        base_params = [
            ("timestamp_received_gte", start_ms),
            ("timestamp_received_lte", end_ms),
            ("sort",  "timestamp_received,desc"),
            ("size",  500),
            ("page",  0),
        ]
        all_events: list[dict] = []

        try:
            resp = await client.get(url, headers=headers, params=base_params, timeout=30)
            if resp.status_code != 200:
                return []

            body  = resp.json()
            emb   = body.get("_embedded", {})
            batch = (
                emb.get("events")
                or emb.get("eventResourceList")
                or emb.get("eventResources")
                or []
            )
            for e in batch:
                e["_deployment_name"] = dep_name
            all_events.extend(batch)

            page_meta  = body.get("page", {})
            total_pages = int(page_meta.get("totalPages", 1))
            page_num    = 1
            while batch and page_num < min(total_pages, 10):
                try:
                    pp = [(k, v) for k, v in base_params if k != "page"] + [("page", str(page_num))]
                    r  = await client.get(url, headers=headers, params=pp, timeout=30)
                    if r.status_code != 200:
                        break
                    emb2  = r.json().get("_embedded", {})
                    batch = (
                        emb2.get("events")
                        or emb2.get("eventResourceList")
                        or emb2.get("eventResources")
                        or []
                    )
                    for e in batch:
                        e["_deployment_name"] = dep_name
                    all_events.extend(batch)
                    page_num += 1
                except Exception:
                    break

        except Exception as e:
            logger.error(f"AV events {dep_name}: {e}")

        logger.info(f"AV: {dep_name} → {len(all_events)} events")
        return all_events

    # ── Fetch for a SPECIFIC deployment by URL ────────────────────────────────

    async def fetch_for_deployment(
        self,
        dep_url: str,
        start_ms: int,
        end_ms: int,
        dep_name: str = "",
    ) -> tuple[list[dict], list[dict]]:
        """Fetch alarms + events for one specific deployment URL."""
        token = await self._get_token()
        if not token:
            raise RuntimeError("AV: authentication failed — check AV_CLIENT_ID / AV_CLIENT_SECRET")

        alarms, events = await asyncio.gather(
            self._fetch_alarms_one(dep_url, dep_name, token, start_ms, end_ms),
            self._fetch_events_one(dep_url, dep_name, token, start_ms, end_ms),
        )
        return alarms, events

    # ── Fetch for ALL deployments (global view) ───────────────────────────────

    async def fetch_all(
        self,
        start_ms: int,
        end_ms: int,
    ) -> tuple[list[dict], list[dict]]:
        """Fetch alarms + events from ALL deployments in parallel (semaphore=4)."""
        token = await self._get_token()
        if not token:
            raise RuntimeError("AV: authentication failed")

        deps = await self.fetch_deployments()
        if not deps:
            return [], []

        sem = asyncio.Semaphore(4)

        async def _one(dep: dict) -> tuple[list, list]:
            dep_url  = dep.get("_resolved_url", "")
            dep_name = dep.get("name", "Unknown")
            async with sem:
                a = await self._fetch_alarms_one(dep_url, dep_name, token, start_ms, end_ms)
                e = await self._fetch_events_one(dep_url, dep_name, token, start_ms, end_ms)
                return a, e

        results = await asyncio.gather(*[_one(d) for d in deps], return_exceptions=True)

        all_alarms: list[dict] = []
        all_events:  list[dict] = []
        for res in results:
            if isinstance(res, tuple):
                a, e = res
                all_alarms.extend(a)
                all_events.extend(e)
            elif isinstance(res, Exception):
                logger.error(f"AV gather error: {res}")

        logger.info(f"AV: fetch_all → {len(all_alarms)} alarms, {len(all_events)} events")
        return all_alarms, all_events


# ─── Module-level singleton ───────────────────────────────────────────────────
_fetcher: Optional[AVFetcher] = None


def get_fetcher() -> AVFetcher:
    global _fetcher
    if _fetcher is None:
        _fetcher = AVFetcher()
    return _fetcher
