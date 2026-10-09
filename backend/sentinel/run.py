"""Per-run context shared by all agents: incident state, evidence store, production IAM model, clock."""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from . import config
from .cloudtrail import short_resource
from .detectors import DetectionEngine
from .iam import IamState
from .integrations import semgrep_label
from .llm import LLM
from .models import AgentStep, Event, Evidence, Integrations, RunState
from .store import get_store


class Run:
    def __init__(self, on_change: Callable[[], None] = lambda: None) -> None:
        self.lock = threading.RLock()
        self.on_change = on_change
        self.store = get_store()
        self.prod = IamState.load()
        self.engine = DetectionEngine(self.store, self.prod)
        self.llm = LLM()
        self.events: list[Event] = []
        self.approval = asyncio.Event()
        self.secret_versions_at_incident: dict[str, int] = {}
        self.wall_opened: float | None = None
        self.wall_contained: float | None = None
        self._clock_base: datetime | None = None
        self._clock_wall = time.monotonic()
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4]
        self.run_dir = config.RUNS_DIR / run_id
        self.state = RunState(
            run_id=run_id,
            integrations=Integrations(
                reasoning=self.llm.label,
                event_store=f"{self.store.name} ({self.store.count():,} baseline events)",
                code_scanner=semgrep_label(),
                threat_intel="offline intel fixture",
                executor="simulated AWS IAM (policy-evaluator sandbox)",
            ),
        )

    # ---- clock: simulated time continues from the last replayed CloudTrail event ----------------

    def set_clock(self, t: datetime) -> None:
        self._clock_base, self._clock_wall = t, time.monotonic()

    def now(self) -> datetime:
        base = self._clock_base or datetime.now(timezone.utc)
        return base + timedelta(seconds=time.monotonic() - self._clock_wall)

    # ---- shared-state helpers -------------------------------------------------------------------

    def changed(self) -> None:
        with self.lock:
            self.state.sim_clock = self.now()
        self.on_change()

    def log(self, agent: str, kind: str, message: str, data: dict[str, Any] | None = None) -> None:
        with self.lock:
            self.state.agent_log.append(AgentStep(t=self.now(), agent=agent, kind=kind, message=message, data=data))
        self.changed()

    def add_evidence(self, source: str, summary: str, raw: Any, ts: datetime | None = None) -> str:
        with self.lock:
            eid = f"E{len(self.state.evidence) + 1}"
            self.state.evidence[eid] = Evidence(id=eid, source=source, timestamp=ts, summary=summary, raw=raw)
        return eid

    def valid_ids(self, ids: list[str]) -> list[str]:
        return [i for i in ids if i in self.state.evidence]

    @property
    def incident(self):
        return self.state.incident

    def attacker_events(self) -> list[Event]:
        who = self.incident.principal
        return [e for e in self.events if self.engine.is_attacker_event(who, e)]

    @staticmethod
    def describe(e: Event) -> str:
        via = f" (session {e.access_key[:4]}…{e.access_key[-4:]})" if e.access_key.startswith("ASIA") else ""
        res = "" if e.resource == "*" else f" → {short_resource(e.resource)}"
        err = f" ✗ {e.error}" if e.error else ""
        return f"{e.name} by {e.principal}{via} from {e.ip}{res}{err}"
