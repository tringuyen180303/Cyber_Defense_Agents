"""Self-improvement loop: Red Team hunts for evasions → Learner proposes changes → Evaluator gates → promote.

Usage: python -m sentinel.selfplay --rounds 2 [--auto-approve] [--reset]
"""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timezone
from typing import Any, Callable

import yaml

from . import knowledge as kb
from .evaluation import evaluate, print_card
from .learner import improve
from .llm import LLM
from .redteam import hunt
from .scenarios import DISCOVERED_DIR, build, load_suite, save_discovered


def learn(*, log: Callable[[str], None] = print, use_llm: bool = False, trigger: str = "manual") -> dict[str, Any]:
    """One learning pass on the current suite; leaves a pending candidate if it found an improvement."""
    k = kb.load()
    suite = load_suite()
    log(f"evaluating knowledge v{k.version} on {len(suite)} scenarios")
    res = improve(k, suite, llm=LLM() if use_llm else None, log=log)
    if not kb.load_scorecard(k.version):
        kb.save_scorecard(k.version, res["base"])
    if not res["accepted"]:
        log("no change improved the scorecard without regressions")
        kb.PENDING.unlink(missing_ok=True)
        return {"pending": None, **_summary(res)}
    pending = {
        "created": datetime.now(timezone.utc).isoformat(), "trigger": trigger, "parent": k.version,
        "summary": "; ".join(c["description"] for c in res["accepted"]),
        "changes": [{k2: v for k2, v in c.items() if k2 != "metrics"} for c in res["accepted"]],
        "base_metrics": res["base"]["metrics"], "metrics": res["card"]["metrics"],
        "base_results": res["base"]["results"], "results": res["card"]["results"],
        "tested": [{k2: v for k2, v in t.items() if k2 in ("type", "description", "verdict", "trigger")}
                   for t in res["tested"]],
        "knowledge": res["knowledge"].d,
    }
    kb.PENDING.write_text(yaml.safe_dump(pending, sort_keys=False, width=110))
    log(f"candidate ready: {pending['summary']}")
    return {"pending": pending, **_summary(res)}


def _summary(res: dict[str, Any]) -> dict[str, Any]:
    return {"base_metrics": res["base"]["metrics"], "metrics": res["card"]["metrics"],
            "tested": len(res["tested"]), "accepted": len(res["accepted"])}


def approve_pending(approved_by: str = "human") -> int:
    p = yaml.safe_load(kb.PENDING.read_text())
    cand = kb.Knowledge(p["knowledge"])
    card = {"version": None, "metrics": p["metrics"], "results": p["results"]}
    v = kb.promote(cand, summary=p["summary"], changes=p["changes"], card=card, approved_by=approved_by)
    card["version"] = v
    kb.save_scorecard(v, card)
    return v


def red_team_round(round_no: int, *, log: Callable[[str], None] = print, budget: int = 40, keep: int = 3) -> int:
    k = kb.load()
    base = [s for s in load_suite(include_discovered=False) if s.label == "attack"]
    known = {s.id for s in load_suite()}
    found = hunt(k, base, seed=round_no, budget=budget, keep=keep, known_ids=known, log=log)
    for spec in found:
        save_discovered(spec)
    return len(found)


def selfplay(rounds: int, *, auto_approve: bool, log: Callable[[str], None] = print, use_llm: bool = False) -> None:
    for r in range(1, rounds + 1):
        log(f"══ round {r}: knowledge v{kb.current_version()} ══")
        log("── learner: fix known gaps on the current suite")
        res = learn(log=log, use_llm=use_llm, trigger=f"self-play round {r}")
        if res["pending"] and auto_approve:
            log(f"promoted v{approve_pending('auto (self-play)')}")
        log("── red team: hunt for evasions against current knowledge")
        n = red_team_round(r, log=log)
        if n:
            log("── learner: close the new gaps")
            res = learn(log=log, use_llm=use_llm, trigger=f"red-team evasions round {r}")
            if res["pending"] and auto_approve:
                log(f"promoted v{approve_pending('auto (self-play)')}")
        if res.get("pending") and not auto_approve:
            log("pending candidate awaits human approval; stopping")
            return


def reset() -> None:
    """Back to hand-written knowledge v1 with no discovered scenarios or memory."""
    for p in kb.VERSIONS.glob("v*.yaml"):
        if p.stem != "v1":
            p.unlink()
    for p in kb.VERSIONS.glob("*.score.json"):
        p.unlink()
    kb.CURRENT.write_text("1\n")
    kb.CHANGELOG.unlink(missing_ok=True)
    kb.PENDING.unlink(missing_ok=True)
    shutil.rmtree(DISCOVERED_DIR, ignore_errors=True)
    shutil.rmtree(kb.MEMORY.parent, ignore_errors=True)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--rounds", type=int, default=2)
    p.add_argument("--auto-approve", action="store_true")
    p.add_argument("--reset", action="store_true")
    p.add_argument("--llm", action="store_true", help="let the LLM propose extra detector rules")
    a = p.parse_args()
    if a.reset:
        reset()
    selfplay(a.rounds, auto_approve=a.auto_approve, use_llm=a.llm)
    k = kb.load()
    print_card(evaluate(k))


if __name__ == "__main__":
    main()
