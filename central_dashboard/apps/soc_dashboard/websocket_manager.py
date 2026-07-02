"""
Sentrium Integrated SOC Dashboard — WebSocket Manager
Manages connected browser clients and broadcasts data updates
with per-role, per-tenant data filtering.
"""

from __future__ import annotations
import json
import logging
from typing import Dict, Optional
from fastapi import WebSocket

logger = logging.getLogger("soc_dashboard.ws")


class WebSocketManager:
    """Manages WebSocket connections with role-aware data isolation."""

    def __init__(self):
        # Maps each WebSocket to its session metadata {role, client_name}
        self._connections: Dict[WebSocket, dict] = {}

    async def connect(
        self,
        ws: WebSocket,
        role: str = "admin",
        client_name: Optional[str] = None,
    ):
        """Accept and register a WebSocket connection with role metadata."""
        await ws.accept()
        self._connections[ws] = {"role": role, "client_name": client_name}
        logger.info(
            f"WebSocket connected: role={role!r} client={client_name!r}. "
            f"Total: {len(self._connections)}"
        )

    def disconnect(self, ws: WebSocket):
        """Remove a disconnected WebSocket."""
        self._connections.pop(ws, None)
        logger.info(f"WebSocket disconnected. Total: {len(self._connections)}")

    @property
    def active_count(self) -> int:
        return len(self._connections)

    def _filter_for(self, data: dict, role: str, client_name: Optional[str]) -> dict:
        """
        Return a copy of `data` scoped to the session's access level.
        - admin / analyst: full unfiltered data
        - client: only their own entry in data["clients"]
        """
        if role != "client" or not client_name:
            return data
        clients_list = data.get("clients", [])
        my_data = [
            c for c in clients_list
            if isinstance(c, dict)
            and c.get("name", "").lower() == client_name.lower()
        ]
        return {**data, "clients": my_data}

    async def broadcast(self, data: dict):
        """
        Broadcast to all connected clients with role-based filtering.
        Client-role users only receive their own tenant's data.
        """
        if not self._connections:
            return

        dead: list[WebSocket] = []

        for ws, meta in self._connections.copy().items():
            role        = meta.get("role", "admin")
            client_name = meta.get("client_name")
            scoped_data = self._filter_for(data, role, client_name)
            try:
                payload = json.dumps(scoped_data, default=str)
                await ws.send_text(payload)
            except Exception as exc:
                logger.warning(f"WebSocket send failed ({role}/{client_name}): {exc}")
                dead.append(ws)

        for ws in dead:
            self._connections.pop(ws, None)

    async def send_to(self, ws: WebSocket, data: dict):
        """Send data to a specific WebSocket connection."""
        try:
            payload = json.dumps(data, default=str)
            await ws.send_text(payload)
        except Exception as exc:
            logger.warning(f"WebSocket send_to failed: {exc}")
            self._connections.pop(ws, None)


# Singleton instance
ws_manager = WebSocketManager()
