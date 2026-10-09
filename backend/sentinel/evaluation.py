"""Eval harness: run every scenario through the full pipeline (offline, deterministic) and score it.

Usage: python -m sentinel.evaluation [--version N]
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from . import knowledge as kb
from . import telemetry
from .commander import run_incident
from .knowledge import Knowledge
from .run import Run
from .scenarios import Scenario, load_suite


@dataclass
class ScenarioResult:
    id: str
    label: str
    expected_incident: bool
    detected: bool
    correct: bool
    confidence: float = 0.0
    events_to_detect: int | None = None
    plan_attempts: int | None = None
    prod_checks_passed: int | None = None
    prod_checks_total: int | None = None
    contained: bool | None = None
    citations_valid: float | None = None
    detectors_fired: list[str] = field(default_factory=list)
    repairs: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


def run_scenario(sc: Scenario, k: Knowledge) -> tuple[ScenarioResult, Run]:
    with telemetry.quiet():
        return _run_scenario(sc, k)


def _run_scenario(sc: Scenario, k: Knowledge) -> tuple[ScenarioResult, Run]:
    run = Run(records=sc.records, knowledge=k, use_llm=False, fast=True, auto_approve=True, persist=False,
              scenario_id=sc.id)
    err = None
    try:
        asyncio.run(run_incident(run))
    except Exception as exc:  # noqa: BLE001
        err = f"{type(exc).__name__}: {exc}"
    inc = run.incident
    fired = sorted({s.detector for e in run.engine.ids.values() for s in e.signals})
    r = ScenarioResult(id=sc.id, label=sc.label, expected_incident=sc.expect_incident, detected=inc is not None,
                       correct=(inc is not None) == sc.expect_incident, detectors_fired=fired, error=err,
                       confidence=max((run.engine.score(w) for w in run.engine.ids), default=0.0))
    if inc:
        atk_idx = [i for i, e in enumerate(run.events) if run.engine.is_attacker_event(inc.principal, e)]
        if atk_idx and run.opened_at_event:
            r.events_to_detect = run.opened_at_event - atk_idx[0]
        r.plan_attempts = max((a.attempt for a in inc.actions), default=None)
        prod = [c for c in inc.verification if c.environment == "production"]
        r.prod_checks_passed, r.prod_checks_total = sum(c.passed for c in prod), len(prod)
        if inc.blast_radius and inc.blast_radius.paths_after is not None:
            r.contained = not any(p.compromised_credential for p in inc.blast_radius.paths_after)
        ids = [i for h in inc.hypotheses for c in h.supporting + h.counter for i in c.evidence_ids]
        r.citations_valid = (sum(i in run.state.evidence for i in ids) / len(ids)) if ids else 1.0
        r.repairs = run.repairs
    if err:
        r.correct = False
    return r, run


def evaluate(k: Knowledge, scenarios: list[Scenario] | None = None,
             on_progress: Callable[[ScenarioResult], None] | None = None,
             runs: dict[str, tuple[Scenario, Run]] | None = None) -> dict[str, Any]:
    scenarios = scenarios if scenarios is not None else load_suite()
    results = []
    for sc in scenarios:
        r, run = run_scenario(sc, k)
        results.append(r)
        if runs is not None:
            runs[sc.id] = (sc, run)
        if on_progress:
            on_progress(r)
    return {"version": k.version, "metrics": metrics(results), "results": [asdict(r) for r in results]}


def _avg(xs: list[float]) -> float:
    return round(sum(xs) / len(xs), 3) if xs else 0.0


def metrics(results: list[ScenarioResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.expected_incident]
    benign = [r for r in results if not r.expected_incident]
    caught = [r for r in attacks if r.detected and not r.error]
    return {
        "scenarios": len(results),
        "attacks": len(attacks),
        "benign": len(benign),
        "recall": _avg([1.0 if r.detected else 0.0 for r in attacks]),
        "false_positives": sum(r.detected for r in benign),
        "avg_attempts": _avg([r.plan_attempts for r in caught if r.plan_attempts]),
        "first_try_rate": _avg([1.0 if r.plan_attempts == 1 else 0.0 for r in caught]),
        "avg_time_to_detect": _avg([r.events_to_detect for r in caught if r.events_to_detect is not None]),
        "contained_rate": _avg([1.0 if r.contained else 0.0 for r in caught]),
        "prod_pass_rate": _avg([1.0 if r.prod_checks_total and r.prod_checks_passed == r.prod_checks_total
                                else 0.0 for r in caught]),
        "citation_validity": _avg([r.citations_valid for r in caught if r.citations_valid is not None]),
        "errors": sum(1 for r in results if r.error),
    }


def print_card(card: dict[str, Any]) -> None:
    print(f"\nKnowledge v{card['version']}")
    print(f"{'scenario':<38} {'label':<7} {'result':<9} {'conf':>5} {'ttd':>4} {'tries':>5} {'prod':>6}  detectors")
    for r in card["results"]:
        res = ("CAUGHT" if r["detected"] else "MISSED") if r["expected_incident"] else \
            ("FALSE+" if r["detected"] else "quiet")
        prod = f"{r['prod_checks_passed']}/{r['prod_checks_total']}" if r["prod_checks_total"] else "-"
        print(f"{r['id']:<38} {r['label']:<7} {res:<9} {r['confidence']:>5.2f} {str(r['events_to_detect'] or '-'):>4} "
              f"{str(r['plan_attempts'] or '-'):>5} {prod:>6}  {','.join(r['detectors_fired'])}"
              + (f"  ERROR {r['error']}" if r["error"] else ""))
    m = card["metrics"]
    print(f"\nrecall {m['recall']:.0%} · false positives {m['false_positives']} · avg attempts {m['avg_attempts']} · "
          f"first-try {m['first_try_rate']:.0%} · events-to-detect {m['avg_time_to_detect']} · contained "
          f"{m['contained_rate']:.0%} · prod pass {m['prod_pass_rate']:.0%} · citations {m['citation_validity']:.0%}"
          f" · errors {m['errors']}")


def main() -> None:
    telemetry.init()
    p = argparse.ArgumentParser()
    p.add_argument("--version", type=int)
    p.add_argument("--save", action="store_true", help="store as the version's scorecard")
    a = p.parse_args()
    k = kb.load(a.version)
    card = evaluate(k)
    print_card(card)
    if a.save:
        kb.save_scorecard(k.version, card)


if __name__ == "__main__":
    main()
