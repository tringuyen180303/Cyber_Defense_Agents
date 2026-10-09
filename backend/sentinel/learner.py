"""Learner + Evaluator gate.

The Learner proposes knowledge changes from what went wrong (missed attacks, false positives, sandbox repairs).
The Evaluator replays the whole suite with each candidate and accepts a change only if it improves the
scorecard without regressing any scenario. Search is greedy: keep the best accepted change, re-propose, repeat.
"""

from __future__ import annotations

import itertools
import json
from typing import Any, Callable

from . import telemetry
from .evaluation import evaluate
from .knowledge import FEATURES, Knowledge
from .llm import LLM
from .run import Run
from .scenarios import Scenario

COMBO_FEATURES = sorted(FEATURES - {"succeeded"})


# ---- changes ------------------------------------------------------------------------------------

def apply_change(k: Knowledge, c: dict[str, Any]) -> Knowledge:
    kk = k.clone()
    d = kk.d
    if c["type"] == "add_rule":
        d["detectors"].append(c["rule"])
    elif c["type"] == "set_weight":
        kk.detector(c["id"])["weight"] = c["weight"]
    elif c["type"] == "set_threshold":
        d["open_threshold"] = c["value"]
    elif c["type"] == "add_playbook":
        d.setdefault("playbooks", []).append(c["playbook"])
    else:
        raise ValueError(c["type"])
    return Knowledge(d)


def describe(c: dict[str, Any]) -> str:
    if c["type"] == "add_rule":
        r = c["rule"]
        return f"new detector {r['id']} (all_of {r['all_of']}, weight {r['weight']})"
    if c["type"] == "set_weight":
        return f"{c['id']} weight {c['old']} → {c['weight']}"
    if c["type"] == "set_threshold":
        return f"open_threshold {c['old']} → {c['value']}"
    pb = c["playbook"]
    return f"playbook {pb['id']}: {pb['when']['kind']} {pb['when'].get('conditions')} → {pb['then']['kind']}"


# ---- proposals ----------------------------------------------------------------------------------

def _event_features(runs: dict[str, tuple[Scenario, Run]]):
    pos: dict[str, list[set[str]]] = {}
    neg: list[set[str]] = []
    for sid, (sc, run) in runs.items():
        for e, feats in run.engine.features_log:
            if sc.label == "attack" and e.id in sc.attacker_event_ids:
                pos.setdefault(sid, []).append(feats)
            else:
                neg.append(feats)
    return pos, neg


def propose(k: Knowledge, card: dict[str, Any], runs: dict[str, tuple[Scenario, Run]],
            llm: LLM | None = None) -> list[dict[str, Any]]:
    results = {r["id"]: r for r in card["results"]}
    missed = [sid for sid, r in results.items() if r["expected_incident"] and not r["detected"]]
    false_pos = [sid for sid, r in results.items() if not r["expected_incident"] and r["detected"]]
    out: list[dict[str, Any]] = []
    existing = {tuple(sorted(d.get("all_of", []))) for d in k.d["detectors"]}

    if missed:
        pos, neg = _event_features(runs)
        scored = []
        feats_in_missed = sorted({f for sid in missed for fs in pos.get(sid, []) for f in fs} & set(COMBO_FEATURES))
        for n in (2, 3):
            for combo in itertools.combinations(feats_in_missed, n):
                cs = set(combo)
                if any(cs <= nf for nf in neg) or any(set(ex) <= cs for ex in existing):
                    continue  # matches benign activity, or only re-counts an existing detector
                covered = [sid for sid in missed if any(cs <= pf for pf in pos.get(sid, []))]
                if covered:
                    scored.append((len(covered), -n, combo, covered))
        scored.sort(reverse=True)
        for cov, _, combo, covered in scored[:4]:
            rid = "learned_" + "_".join(c.replace("_resource", "").replace("_", "") for c in combo)
            out.append({"type": "add_rule", "trigger": f"missed {', '.join(covered)}", "rule": {
                "id": rid, "kind": "rule", "weight": 0.4, "severity": 7, "all_of": list(combo),
                "subject": ["resource"] if {"data_action", "critical_resource", "denied"} & set(combo) else ["key"],
                "title": f"Learned pattern ({' + '.join(combo)}): {{principal}} {{action}} {{resource}} from {{ip}}",
                "learned_from": covered}})
        for sid in missed:
            for did in results[sid]["detectors_fired"]:
                det = k.detector(did)
                if det and det["weight"] + 0.1 <= 0.6:
                    out.append({"type": "set_weight", "id": did, "old": det["weight"],
                                "weight": round(det["weight"] + 0.1, 2), "trigger": f"missed {sid}"})
        out.append({"type": "set_threshold", "old": k.d["open_threshold"],
                    "value": round(k.d["open_threshold"] - 0.05, 2), "trigger": f"missed {', '.join(missed)}"})

    if false_pos:
        for sid in false_pos:
            for did in results[sid]["detectors_fired"]:
                det = k.detector(did)
                for delta in (0.1, 0.15):
                    if det and det["weight"] - delta >= 0.05:
                        out.append({"type": "set_weight", "id": did, "old": det["weight"],
                                    "weight": round(det["weight"] - delta, 2), "trigger": f"false positive {sid}"})
        out.append({"type": "set_threshold", "old": k.d["open_threshold"],
                    "value": round(k.d["open_threshold"] + 0.05, 2), "trigger": f"false positive {', '.join(false_pos)}"})

    have = {(pb["when"]["kind"], tuple(pb["when"].get("conditions", []))) for pb in k.playbooks}
    for r in card["results"]:
        for rep in r.get("repairs", []):
            key = (rep["culprit_kind"], tuple(rep["conditions"]))
            if key in have or not rep["conditions"]:
                continue
            have.add(key)
            pid = f"PB-{len(k.playbooks) + 1 + sum(c['type'] == 'add_playbook' for c in out)}"
            out.append({"type": "add_playbook", "trigger": f"sandbox repair in {r['id']}", "playbook": {
                "id": pid, "when": {"kind": rep["culprit_kind"], "conditions": list(rep["conditions"])},
                "then": {"kind": rep["replacement_kind"]},
                "reason": f"{rep['culprit_kind']} with {', '.join(rep['conditions'])} broke: "
                          f"{rep['failed_checks'][0] if rep['failed_checks'] else 'legitimate workload'}",
                "learned_from": f"scenario {rep['scenario']}" if rep["incident"] == "INC-EVAL"
                                else f"{rep['incident']} ({rep['scenario'] or 'live'})"}})

    if llm and llm.available and missed:
        out += _llm_rules(llm, k, missed, runs)
    for c in out:
        c["description"] = describe(c)
        c["id"] = c.get("id") or (c.get("rule") or c.get("playbook") or {}).get("id") or "open_threshold"
    return out


def _llm_rules(llm: LLM, k: Knowledge, missed: list[str], runs) -> list[dict[str, Any]]:
    pos, neg = _event_features(runs)
    payload = {"features": sorted(FEATURES), "existing_detectors": [d["id"] for d in k.d["detectors"]],
               "missed_attack_event_features": {s: [sorted(f) for f in pos.get(s, [])][:12] for s in missed},
               "benign_event_feature_samples": [sorted(f) for f in neg[:40]]}
    try:
        out = llm.json("You are a detection engineer. Propose up to 2 detector rules (feature conjunctions) that "
                       "catch the missed attacks without matching benign events. JSON: {\"rules\": [{\"id\": str, "
                       "\"all_of\": [feature], \"rationale\": str}]}", json.dumps(payload))
    except Exception:  # noqa: BLE001
        return []
    rules = []
    for r in out.get("rules", [])[:2]:
        feats = [f for f in r.get("all_of", []) if f in FEATURES]
        if len(feats) >= 2:
            rules.append({"type": "add_rule", "trigger": f"LLM proposal for {', '.join(missed)}", "rule": {
                "id": "llm_" + str(r.get("id", "rule"))[:30].replace(" ", "_"), "kind": "rule", "weight": 0.4,
                "severity": 7, "all_of": feats, "subject": ["resource"],
                "title": f"LLM-proposed pattern ({' + '.join(feats)}): {{principal}} {{action}} {{resource}}"}})
    return rules


# ---- evaluator gate -----------------------------------------------------------------------------

def objective(card: dict[str, Any]) -> tuple:
    m = card["metrics"]
    correct = sum(r["correct"] for r in card["results"])
    return (correct, -m["errors"], m["contained_rate"], m["prod_pass_rate"], -m["avg_attempts"],
            -m["avg_time_to_detect"])


def regressions(base: dict[str, Any], card: dict[str, Any]) -> list[str]:
    b = {r["id"]: r for r in base["results"]}
    out = [f"{r['id']} now {'missed' if r['expected_incident'] else 'false positive'}" for r in card["results"]
           if b.get(r["id"], {}).get("correct") and not r["correct"]]
    for k in ("contained_rate", "prod_pass_rate", "citation_validity"):
        if card["metrics"][k] < base["metrics"][k] - 1e-9:
            out.append(f"{k} {base['metrics'][k]} → {card['metrics'][k]}")
    if card["metrics"]["errors"] > base["metrics"]["errors"]:
        out.append("pipeline errors increased")
    return out


@telemetry.traced("learning.improve")
def improve(k: Knowledge, scenarios: list[Scenario], *, max_steps: int = 4, llm: LLM | None = None,
            log: Callable[[str], None] = print) -> dict[str, Any]:
    runs: dict[str, tuple[Scenario, Run]] = {}
    base = evaluate(k, scenarios, runs=runs)
    cur_k, cur_card, cur_runs = k, base, runs
    accepted: list[dict[str, Any]] = []
    tested: list[dict[str, Any]] = []
    for step in range(max_steps):
        cands = propose(cur_k, cur_card, cur_runs, llm)
        if not cands:
            break
        log(f"learner step {step + 1}: {len(cands)} candidate change(s)")
        best = None
        for c in cands:
            try:
                kk = apply_change(cur_k, c)
            except ValueError as exc:
                tested.append({**c, "verdict": f"invalid: {exc}"})
                continue
            rr: dict[str, tuple[Scenario, Run]] = {}
            with telemetry.span("learning.candidate", **{"sentinel.change_type": c["type"],
                                                         "sentinel.change": c["description"],
                                                         "sentinel.trigger": c.get("trigger"),
                                                         "sentinel.step": step + 1}) as sp:
                card = evaluate(kk, scenarios, runs=rr)
                regs = regressions(cur_card, card)
                better = objective(card) > objective(cur_card)
                verdict = "rejected: " + "; ".join(regs) if regs else ("improves" if better else "no improvement")
                m = card["metrics"]
                sp.set(**{"sentinel.verdict": verdict.split(":")[0], "sentinel.verdict_detail": verdict,
                          "sentinel.recall": m["recall"], "sentinel.false_positives": m["false_positives"],
                          "sentinel.avg_attempts": m["avg_attempts"], "sentinel.regressions": regs})
            tested.append({**c, "verdict": verdict, "metrics": card["metrics"]})
            log(f"  {'✓' if not regs and better else '✗'} {c['description']} — {verdict}")
            if not regs and better and (best is None or objective(card) > objective(best[1])):
                best = (c, card, kk, rr)
        if not best:
            break
        c, cur_card, cur_k, cur_runs = best
        accepted.append(c)
        log(f"  accepted: {c['description']}")
    telemetry.annotate(**{"sentinel.knowledge_version": k.version, "sentinel.candidates_tested": len(tested),
                          "sentinel.accepted": [c["description"] for c in accepted]})
    return {"base": base, "card": cur_card, "knowledge": cur_k, "accepted": accepted, "tested": tested}
