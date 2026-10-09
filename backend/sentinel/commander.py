"""Incident Commander: owns the lifecycle and delegates to specialist agents through shared incident state."""

from __future__ import annotations

import asyncio
import time

from .agents import Investigator, Planner, Verifier, blast_radius, execute, finalize_blast_radius, postmortem, \
    reconstruct, remember_incident
from .cloudtrail import Normalizer, parse_time
from .models import Incident, StreamEvent
from .run import Run

CMD = "Incident Commander"
MAX_ATTEMPTS = 3


def _sync_prod_state(run: Run, e) -> None:
    """Mirror CloudTrail write events into the production IAM model."""
    if not e.succeeded:
        return
    if e.name == "CreateAccessKey":
        k = (e.raw.get("responseElements") or {}).get("accessKey", {})
        if k.get("accessKeyId") and not run.prod.key(k["accessKeyId"]):
            run.prod.add_key(k["userName"], k["accessKeyId"], e.time)
    elif e.name == "AssumeRole":
        sk = (e.raw.get("responseElements") or {}).get("credentials", {}).get("accessKeyId")
        role = e.resource.rsplit("/", 1)[-1]
        if sk and role in run.prod.roles:
            run.prod.register_session(sk, role, e.time, e.origin_user, e.access_key)
    elif e.name == "GetSecretValue":
        res = run.prod.resource(e.resource)
        if res and run.engine.is_attacker_event(e.origin_user or e.principal, e):
            run.secret_versions_at_incident.setdefault(e.resource, res.get("version", 1))


async def replay(run: Run) -> None:
    records = run.records
    norm = Normalizer()
    k = run.knowledge
    run.state.phase = "replaying"
    run.state.total_events = len(records)
    run.set_clock(parse_time(records[0]["eventTime"]))
    run.log("Detection", "start", f"Streaming {len(records)} CloudTrail events against "
                                  f"{run.store.count():,}-event baseline ({run.store.name})")
    for rec in records:
        eid = f"E{len(run.state.evidence) + 1}"
        e = norm(rec, eid)
        run.add_evidence("cloudtrail", Run.describe(e), rec, e.time)
        run.events.append(e)
        run.set_clock(e.time)
        signals = run.engine.observe(e)
        _sync_prod_state(run, e)
        with run.lock:
            run.state.events.append(StreamEvent(
                evidence_id=eid, time=e.time, name=e.name, source=e.source, principal=e.principal,
                access_key=e.access_key, ip=e.ip, resource=e.resource, error=e.error,
                detectors=[s.detector for s in signals]))
        for s in signals:
            run.log("Detection", "result", f"[{s.detector}] {s.title}", {"evidence_ids": s.evidence_ids})
        who = e.origin_user or e.principal
        score = run.engine.score(who)
        inc = run.state.incident
        if signals and inc is None and score >= k.d["open_threshold"] and \
                len({s.detector for s in run.engine.ids[who].signals}) >= k.d.get("min_detectors", 2):
            run.wall_opened = time.monotonic()
            run.opened_at_event = len(run.events)
            with run.lock:
                run.state.incident = Incident(
                    id=run.incident_id, title="Possible credential compromise", severity="SEV-2",
                    status="investigating", principal=who, opened_at=e.time, confidence=score)
            run.log(CMD, "decision", f"Incident {run.incident_id} opened for {who} (detection confidence {score:.0%})")
        if run.state.incident and run.state.incident.principal == who:
            inc = run.state.incident
            with run.lock:
                inc.signals = list(run.engine.ids[who].signals)
                inc.confidence = score
                if score >= k.d.get("sev1_threshold", 0.85) and inc.severity != "SEV-1":
                    inc.severity = "SEV-1"
                    run.log(CMD, "decision", f"Escalated to SEV-1 (confidence {score:.0%})")
        run.changed()
        if run.replay_delay:
            await asyncio.sleep(run.replay_delay)
    if run.state.incident:
        atk = run.attacker_events()
        with run.lock:
            run.state.incident.attacker_ips = sorted({e.ip for e in atk})
            minted = {k for k, ev in run.engine.minted_keys.items() if ev in atk}
            run.state.incident.attacker_keys = sorted({e.access_key for e in atk} |
                                                      {e.origin_key for e in atk if e.origin_key} | minted)
        run.set_clock(run.events[-1].time)


async def pace(run: Run) -> None:
    if run.agent_pace:
        await asyncio.sleep(run.agent_pace)


async def run_incident(run: Run) -> None:
    try:
        await _run(run)
    except Exception as exc:  # noqa: BLE001
        run.state.phase = "failed"
        run.state.error = f"{type(exc).__name__}: {exc}"
        run.log(CMD, "error", f"Pipeline failed: {exc}")
        raise


async def _run(run: Run) -> None:
    run.state.started_at = run.now()
    await replay(run)
    inc = run.incident
    if inc is None:
        run.state.phase = "resolved"
        run.log(CMD, "result", "No incident: activity within baseline")
        return

    run.state.phase = "investigating"
    run.log(CMD, "handoff", "Dispatching Investigator, Reconstruction and Blast Radius in parallel",
            {"agents": ["Investigator", "Reconstruction", "Blast Radius"]})
    await asyncio.gather(asyncio.to_thread(Investigator(run).run_agent), asyncio.to_thread(reconstruct, run),
                         asyncio.to_thread(blast_radius, run))
    top = inc.hypotheses[0]
    with run.lock:
        inc.title = top.title
        inc.status = "containing"
    run.log(CMD, "decision", f"Root cause accepted: {top.title} ({top.confidence:.0%}). Handing off to planning")
    await pace(run)

    planner, verifier = Planner(run), Verifier(run)
    run.state.phase = "verifying"
    actions = await asyncio.to_thread(planner.plan)
    await pace(run)
    for attempt in range(1, MAX_ATTEMPTS + 1):
        run.log(CMD, "handoff", f"Plan v{attempt} → Verifier (sandbox)")
        ok, failures, culprits = await asyncio.to_thread(verifier.sandbox, actions, attempt)
        await pace(run)
        if ok:
            break
        if attempt == MAX_ATTEMPTS:
            run.state.phase = "failed"
            run.log(CMD, "error", "Could not find a plan that passes verification; paging a human")
            return
        actions = await asyncio.to_thread(planner.revise, actions, failures, culprits, attempt + 1)
        await pace(run)

    for a in actions:
        if a.status == "sandbox_pass":
            a.status = "approved" if a.risk == "safe" else "awaiting_approval"
    safe = [a for a in actions if a.status == "approved"]
    run.state.phase = "executing"
    run.log(CMD, "decision", f"Auto-executing {len(safe)} SAFE action(s); "
                             f"{sum(a.status == 'awaiting_approval' for a in actions)} REVIEW action(s) need approval")
    await asyncio.to_thread(execute, run, actions, verifier)
    await pace(run)

    if any(a.status == "awaiting_approval" for a in actions):
        if run.auto_approve:
            for a in actions:
                if a.status == "awaiting_approval":
                    a.status = "approved"
            run.log(CMD, "decision", "Auto-approved REVIEW actions (auto-approve mode)")
        else:
            run.state.phase = "awaiting_approval"
            run.log(CMD, "handoff", "Waiting for human approval of REVIEW actions (sandbox-verified)")
            await run.approval.wait()
        run.state.phase = "executing"
        await asyncio.to_thread(execute, run, actions, verifier)

    final_attempt = max(a.attempt for a in actions)
    ok = await asyncio.to_thread(verifier.production, actions, final_attempt)
    run.wall_contained = time.monotonic()
    await asyncio.to_thread(finalize_blast_radius, run)
    with run.lock:
        inc.status = "resolved" if ok else "contained (verification failures)"
        inc.resolved_at = run.now()
    await asyncio.to_thread(postmortem, run)
    if run.persist:
        remember_incident(run)
    run.state.phase = "resolved"
    run.log(CMD, "result", f"Incident {inc.id} {inc.status}")


def decide(run: Run, approve: list[str] | None, reject: list[str] | None) -> None:
    inc = run.incident
    if not inc:
        return
    for a in inc.actions:
        if a.status != "awaiting_approval":
            continue
        if reject and a.id in reject:
            a.status, a.status_reason = "blocked", "rejected by human reviewer"
            run.log("Human", "decision", f"Rejected {a.id}: {a.title}")
        elif approve is None or a.id in approve:
            a.status = "approved"
            run.log("Human", "decision", f"Approved {a.id}: {a.title}")
    if not any(a.status == "awaiting_approval" for a in inc.actions):
        run.approval.set()
    run.changed()
