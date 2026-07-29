"""
AlienVault USM Anywhere — FastAPI Router
==========================================
Replaces all Flask /api/alienvault/* routes with native async FastAPI endpoints.
Uses AVFetcher (exact SOC dashboard tech stack: httpx.AsyncClient, asyncio).

Mount point: /api/av  (set in asgi.py)
"""
from __future__ import annotations

import logging
import urllib.parse
from io import BytesIO
from typing import Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from apps.alienvault.av_fetcher import get_fetcher, _av_configured
from apps.alienvault.logic import process_alarms, process_events, export_to_excel

logger = logging.getLogger("alienvault.router")

# ─── SSRF protection ─────────────────────────────────────────────────────────
_ALLOWED_HOSTS = ("alienvault.cloud", "alienvault.com")

def _valid_dep_url(url: str) -> bool:
    if not url:
        return True  # empty = use global fetch
    try:
        p = urllib.parse.urlparse(url)
        if p.scheme != "https":
            return False
        host = p.netloc.lower().split(":")[0]
        return any(host == d or host.endswith("." + d) for d in _ALLOWED_HOSTS)
    except Exception:
        return False


# ─── FastAPI sub-application ──────────────────────────────────────────────────
av_app = FastAPI(title="AlienVault AV API", docs_url=None, redoc_url=None)


# ─── Request / Response models ────────────────────────────────────────────────
class FetchRequest(BaseModel):
    dep_url:  str = ""
    start_ms: int
    end_ms:   int


class DeploymentItem(BaseModel):
    id:          str = ""
    name:        str = ""
    displayName: str = ""
    url:         str = ""


# ─── Routes ───────────────────────────────────────────────────────────────────

@av_app.get("/health")
async def health():
    return {"ok": True, "configured": _av_configured()}


@av_app.get("/deployments")
async def deployments():
    """Return deployment list for the UI dropdown."""
    if not _av_configured():
        raise HTTPException(503, "AlienVault not configured")
    fetcher = get_fetcher()
    try:
        deps = await fetcher.fetch_deployments()
    except Exception as e:
        logger.exception("deployments error")
        raise HTTPException(500, str(e))

    return [
        {
            "id":          d.get("id", ""),
            "name":        d.get("name", d.get("displayName", "Unknown")),
            "displayName": d.get("displayName", d.get("name", "Unknown")),
            "url":         d.get("_resolved_url", ""),
        }
        for d in deps
    ]


@av_app.post("/fetch")
async def fetch(req: FetchRequest):
    """Fetch alarms + events for a specific deployment or all deployments."""
    dep_url = req.dep_url.strip()
    if not _valid_dep_url(dep_url):
        logger.warning(f"SSRF blocked: dep_url={dep_url!r}")
        raise HTTPException(400, "Invalid deployment URL")

    fetcher = get_fetcher()
    try:
        if dep_url:
            # Find dep_name from cached deployments (best effort)
            deps     = fetcher._deployments or []
            dep_name = next(
                (d.get("name", "") for d in deps if d.get("_resolved_url") == dep_url),
                dep_url.split("//")[-1].split(".")[0],
            )
            alarms, events = await fetcher.fetch_for_deployment(dep_url, req.start_ms, req.end_ms, dep_name)
            strategy = f"per_deployment:{dep_url}"
        else:
            alarms, events = await fetcher.fetch_all(req.start_ms, req.end_ms)
            strategy = "all_deployments"
    except Exception as e:
        logger.exception("fetch error")
        raise HTTPException(500, str(e))

    logger.info(f"AV fetch [{strategy}]: {len(alarms)} alarms, {len(events)} events")
    return {
        "alarm_data":  process_alarms(alarms)  if alarms  else {},
        "event_data":  process_events(events)  if events  else {},
        "alarm_count": len(alarms),
        "event_count": len(events),
        "strategy":    strategy,
    }


@av_app.post("/export")
async def export(req: FetchRequest):
    """Fetch and export alarms + events to Excel."""
    dep_url = req.dep_url.strip()
    if not _valid_dep_url(dep_url):
        raise HTTPException(400, "Invalid deployment URL")

    fetcher = get_fetcher()
    try:
        if dep_url:
            deps     = fetcher._deployments or []
            dep_name = next(
                (d.get("name", "") for d in deps if d.get("_resolved_url") == dep_url),
                dep_url.split("//")[-1].split(".")[0],
            )
            alarms, events = await fetcher.fetch_for_deployment(dep_url, req.start_ms, req.end_ms, dep_name)
        else:
            alarms, events = await fetcher.fetch_all(req.start_ms, req.end_ms)
    except Exception as e:
        logger.exception("export error")
        raise HTTPException(500, str(e))

    buf = export_to_excel(
        process_alarms(alarms)  if alarms  else {},
        process_events(events)  if events  else {},
    )
    return StreamingResponse(
        buf,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=alienvault_report.xlsx"},
    )
