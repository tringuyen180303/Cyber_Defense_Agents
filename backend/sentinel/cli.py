"""Headless run: python -m sentinel.cli  (no delays, auto-approves REVIEW actions)."""

from __future__ import annotations

import asyncio
import os

os.environ.setdefault("SENTINEL_REPLAY_DELAY", "0")
os.environ.setdefault("SENTINEL_AGENT_PACE", "0")
os.environ.setdefault("SENTINEL_AUTO_APPROVE", "1")

from .commander import run_incident  # noqa: E402
from .run import Run  # noqa: E402


def main() -> Run:
    from . import telemetry

    telemetry.init()
    run = Run()
    asyncio.run(run_incident(run))
    for s in run.state.agent_log:
        print(f"{s.t:%H:%M:%S}  {s.agent:<20} {s.kind:<9} {s.message}")
    inc = run.incident
    if inc:
        print("\n" + (inc.postmortem or ""))
    return run


if __name__ == "__main__":
    main()
