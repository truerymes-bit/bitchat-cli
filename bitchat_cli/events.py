"""Lightweight async event bridge between networking and the TUI.

The networking layer (BLEService) publishes events; the Textual app consumes
them. Networking remains the sole producer of these events; the UI never
mutates protocol state.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Any


GENERAL = "general"


class EventType(str, Enum):
    OUTPUT = "output"   # a themed line that used to go to stdout
    STATUS = "status"   # request to refresh status widgets
    DM_STATUS = "dm_status"  # payload {conv, msg_id, state}: outgoing DM delivery state changed


@dataclass
class AppEvent:
    type: EventType
    payload: Any = None
    conv: str | None = None
    msg_id: str | None = None
    is_self: bool = False


class EventBus:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[AppEvent] = asyncio.Queue()

    def publish_nowait(self, event: AppEvent) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass

    async def publish(self, event: AppEvent) -> None:
        await self.queue.put(event)

    async def get(self) -> AppEvent:
        return await self.queue.get()
