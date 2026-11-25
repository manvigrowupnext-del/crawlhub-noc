"""In-process real-time SSE pub/sub event bus for the Jarvis Mission Control UI."""
from __future__ import annotations
import asyncio
import json
from typing import Any


class EventBus:
    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)

    def publish(self, event_type: str, payload: dict[str, Any]):
        msg = json.dumps({"type": event_type, **payload})
        dead = []
        for q in list(self._subscribers):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._subscribers.discard(q)


bus = EventBus()
