"""HTTP endpoints for the self-improvement loop (mounted by api.py)."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from . import knowledge as kb
from .evaluation import evaluate
from .scenarios import DISCOVERED_DIR, load_suite
from .selfplay import approve_pending, learn, red_team_round, reset

router = APIRouter(prefix="/api/learning")


class LearningState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.running: str | None = None
        self.log: list[dict[str, str]] = []
        self._matrix_key: tuple | None = None
        self._matrix: dict[str, Any] | None = None

    def write(self, msg: str) -> None:
        with self.lock:
            self.log.append({"t": datetime.now(timezone.utc).isoformat(), "msg": msg})
            self.log = self.log[-400:]

    def matrix(self) -> dict[str, Any]:
        """Every knowledge version evaluated on the *current* suite, so columns are comparable."""
        suite = load_suite()
        key = (tuple(kb.versions()), tuple(s.id for s in suite))
        if key != self._matrix_key:
            cards = {v: evaluate(kb.load(v), suite) for v in kb.versions()}
            self._matrix = {
                "scenarios": [{"id": s.id, "label": s.label, "source": s.source, "description": s.description,
                               "provenance": s.spec.get("provenance")} for s in suite],
                "versions": {v: {"metrics": c["metrics"],
                                 "results": {r["id"]: {k: r[k] for k in ("detected", "correct", "confidence",
                                                                         "plan_attempts", "events_to_detect")}
                                             for r in c["results"]}} for v, c in cards.items()},
            }
            self._matrix_key = key
        return self._matrix


state = LearningState()


async def _background(name: str, fn, *args, **kw) -> None:
    if state.running:
        raise HTTPException(409, f"{state.running} already running")
    state.running = name

    def work():
        try:
            fn(*args, log=state.write, **kw)
        except Exception as exc:  # noqa: BLE001
            state.write(f"ERROR: {type(exc).__name__}: {exc}")
        finally:
            state.running = None

    asyncio.get_running_loop().run_in_executor(None, work)


@router.get("")
async def overview() -> dict[str, Any]:
    versions = []
    for v in kb.versions():
        k = kb.load(v)
        versions.append({"version": v, "parent": k.d.get("parent"), "created": k.d.get("created"),
                         "summary": k.d.get("summary"), "detectors": len(k.detectors),
                         "learned_detectors": sum(1 for d in k.detectors if d["id"].startswith(("learned_", "llm_"))),
                         "playbooks": len(k.playbooks), "open_threshold": k.d["open_threshold"]})
    pending = yaml.safe_load(kb.PENDING.read_text()) if kb.PENDING.exists() else None
    if pending:
        for key in ("knowledge", "base_results", "results"):
            pending.pop(key, None)
    matrix = await asyncio.to_thread(state.matrix) if not state.running else state._matrix
    return {
        "current": kb.current_version(), "versions": versions, "pending": pending, "running": state.running,
        "log": state.log[-150:], "changelog": kb.changelog(), "memories": len(kb.memories()),
        "recent_memories": kb.memories()[-5:], "knowledge_yaml": kb.load().dump(), "matrix": matrix,
    }


class Rounds(BaseModel):
    budget: int = 40


@router.post("/learn")
async def learn_now() -> dict:
    await _background("learner", learn, trigger="dashboard")
    return {"ok": True}


@router.post("/redteam")
async def redteam(body: Rounds | None = None) -> dict:
    def rt_then_learn(log):
        n = red_team_round(kb.current_version() * 10 + len(list(DISCOVERED_DIR.glob("*.yaml"))), log=log, budget=(body.budget if body else 40))
        if n:
            log("── learner: closing the new gaps")
            learn(log=log, trigger="red-team evasions")
        else:
            log("no evasions found against current knowledge")

    await _background("red team", rt_then_learn)
    return {"ok": True}


@router.post("/approve")
async def approve() -> dict:
    if not kb.PENDING.exists():
        raise HTTPException(404, "no pending candidate")
    v = await asyncio.to_thread(approve_pending, "human (dashboard)")
    state.write(f"promoted knowledge v{v}")
    return {"version": v}


@router.post("/reject")
async def reject() -> dict:
    kb.PENDING.unlink(missing_ok=True)
    state.write("candidate rejected by human")
    return {"ok": True}


class Rollback(BaseModel):
    version: int


@router.post("/rollback")
async def rollback(body: Rollback) -> dict:
    kb.rollback(body.version)
    state.write(f"rolled back to v{body.version}")
    return {"ok": True}


@router.post("/reset")
async def reset_learning() -> dict:
    if state.running:
        raise HTTPException(409, "busy")
    reset()
    state.log.clear()
    state._matrix_key = None
    state.write("reset to hand-written knowledge v1")
    return {"ok": True}
