"""HTTP API + server-sent events for the dashboard."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .commander import decide, run_incident
from .run import Run
from .store import get_store

log = logging.getLogger("sentinel")
app = FastAPI(title="Sentinel")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class Hub:
    def __init__(self) -> None:
        self.run: Run | None = None
        self.task: asyncio.Task | None = None
        self.subscribers: set[asyncio.Queue] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._pending = False

    def snapshot(self) -> str:
        if not self.run:
            return json.dumps({"phase": "idle"})
        with self.run.lock:
            return self.run.state.model_dump_json()

    def notify(self) -> None:
        """Called from any thread; coalesces bursts of changes into one broadcast."""
        if self.loop is None or self._pending:
            return
        self._pending = True
        self.loop.call_soon_threadsafe(lambda: self.loop.call_later(0.05, self._flush))

    def _flush(self) -> None:
        self._pending = False
        data = self.snapshot()
        for q in list(self.subscribers):
            if q.qsize() > 5:
                while not q.empty():
                    q.get_nowait()
            q.put_nowait(data)


hub = Hub()


@app.on_event("startup")
async def startup() -> None:
    hub.loop = asyncio.get_running_loop()
    await asyncio.to_thread(get_store)


class Decision(BaseModel):
    approve: list[str] | None = None
    reject: list[str] | None = None


@app.post("/api/simulate")
async def simulate() -> dict:
    if hub.task and not hub.task.done():
        hub.task.cancel()
    hub.run = Run(on_change=hub.notify)
    hub.task = asyncio.create_task(run_incident(hub.run))
    hub.notify()
    return {"run_id": hub.run.state.run_id}


@app.post("/api/reset")
async def reset() -> dict:
    if hub.task and not hub.task.done():
        hub.task.cancel()
    hub.run, hub.task = None, None
    hub.notify()
    return {"ok": True}


@app.post("/api/decision")
async def decision(body: Decision) -> dict:
    if not hub.run or not hub.run.incident:
        raise HTTPException(404, "no active incident")
    decide(hub.run, body.approve, body.reject)
    return {"ok": True}


@app.get("/api/state")
async def state():
    return json.loads(hub.snapshot())


@app.get("/api/postmortem.md")
async def postmortem_md():
    from fastapi.responses import PlainTextResponse

    if not hub.run or not hub.run.incident or not hub.run.incident.postmortem:
        raise HTTPException(404, "no postmortem yet")
    return PlainTextResponse(hub.run.incident.postmortem, media_type="text/markdown")


@app.get("/api/stream")
async def stream():
    q: asyncio.Queue = asyncio.Queue()
    hub.subscribers.add(q)
    q.put_nowait(hub.snapshot())

    async def gen():
        try:
            while True:
                yield {"event": "state", "data": await q.get()}
        finally:
            hub.subscribers.discard(q)

    return EventSourceResponse(gen(), ping=15)
