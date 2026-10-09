"""Red Team agent: mutates known attacks into variants and keeps the ones that evade current detection.

Mutations are deterministic operators on scenario specs (an LLM can propose operator combinations, but every
variant is still built by the scenario engine, so it is always a concrete, replayable CloudTrail sequence).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import random
from typing import Any, Callable

from . import telemetry
from .evaluation import run_scenario
from .knowledge import Knowledge
from .scenarios import Scenario, build, clone_spec

CRITICAL_BUCKETS = {"customer-documents", "model-artifacts"}


def _attacker_steps(spec: dict[str, Any]):
    return [s for s in spec["steps"] if "api" in s and not s.get("legit")]


def _relative(spec: dict[str, Any]) -> None:
    """Replace absolute step times with gaps so steps can be re-paced."""
    prev = None
    for s in spec["steps"]:
        if "at" in s:
            hh, mm, ss = (int(x) for x in str(s.pop("at")).split(":"))
            cur = hh * 3600 + mm * 60 + ss
            s["after"] = max(1, cur - prev) if prev is not None else cur - _start_seconds(spec)
            prev = cur + (int(s.get("count", 1)) - 1) * float(s.get("spacing", 3))
        else:
            prev = (prev or _start_seconds(spec)) + float(s.get("after", 20)) + \
                (int(s.get("count", 1)) - 1) * float(s.get("spacing", 3))


def _start_seconds(spec: dict[str, Any]) -> int:
    t = str(spec.get("start", "2026-10-07T02:25:00Z"))[11:19]
    hh, mm, ss = (int(x) for x in t.split(":"))
    return hh * 3600 + mm * 60 + ss


def op_known_network(spec):
    spec.setdefault("attacker", {}).update(ip="github2", ua="ci")


def op_drop_discovery(spec):
    spec["steps"] = [s for s in spec["steps"] if not (
        "api" in s and (s["api"].startswith(("iam:List", "iam:Get")) or s["api"] == "sts:GetCallerIdentity"))]


def op_drop_persistence(spec):
    spec["steps"] = [s for s in spec["steps"] if s.get("api") != "iam:CreateAccessKey"]
    for s in spec["steps"]:
        if s.get("as") == "minted":
            s["as"] = "leaked"


def op_retarget(spec):
    for s in spec["steps"]:
        if s.get("bucket") == "customer-documents":
            s["bucket"] = "model-artifacts"
            s.pop("keys", None)
            s["prefix"] = "weights/v7"


def op_slow(spec):
    _relative(spec)
    for s in _attacker_steps(spec):
        s["after"] = 150
        if int(s.get("count", 1)) > 1:
            s["spacing"] = 90


def op_secrets_focus(spec):
    spec["steps"] = [s for s in spec["steps"] if not ("api" in s and s["api"].startswith("s3:"))]
    if not any(s.get("secret") == "prod/db-password" for s in spec["steps"]):
        spec["steps"].append({"api": "secretsmanager:GetSecretValue", "as": "session", "after": 30,
                              "secret": "prod/db-password", "error": "AccessDenied", "count": 3, "spacing": 20})


OPERATORS: dict[str, Callable[[dict], None]] = {
    "known_network": op_known_network,
    "drop_discovery": op_drop_discovery,
    "drop_persistence": op_drop_persistence,
    "retarget": op_retarget,
    "slow": op_slow,
    "secrets_focus": op_secrets_focus,
}


def _valid(spec: dict[str, Any]) -> bool:
    """A variant must still be an attack: touch a critical asset or plant persistence, with a usable session."""
    steps = _attacker_steps(spec)
    have = {"leaked"}
    for s in steps:
        if s.get("as", "leaked") not in have:
            return False
        if s["api"] == "iam:CreateAccessKey":
            have.add("minted")
        if s["api"] == "sts:AssumeRole":
            have.add("session")
    return any(s.get("bucket") in CRITICAL_BUCKETS or s.get("secret") or s["api"] == "iam:CreateAccessKey"
               for s in steps)


def variants(base: list[Scenario], seed: int, max_ops: int = 3) -> list[dict[str, Any]]:
    out, seen = [], set()
    for sc in base:
        if sc.label != "attack":
            continue
        for n in range(2, max_ops + 1):
            for ops in itertools.combinations(OPERATORS, n):
                spec = clone_spec(sc.spec)
                if spec.get("provenance"):
                    continue
                for op in ops:
                    OPERATORS[op](spec)
                if not _valid(spec):
                    continue
                sig = hashlib.sha1(json.dumps(spec["steps"], sort_keys=True, default=str).encode()).hexdigest()[:8]
                if sig in seen:
                    continue
                seen.add(sig)
                spec["id"] = f"rt-{sc.id.removeprefix('attack-')}-{'+'.join(o.replace('_', '-') for o in ops)}"
                spec["description"] = f"Red-team variant of {sc.id}: {', '.join(ops)}"
                spec["seed"] = int(sig, 16) % 10_000
                spec["provenance"] = {"generated_by": "red-team", "base": sc.id, "operators": list(ops),
                                      "seed": seed}
                out.append(spec)
    random.Random(seed).shuffle(out)
    return out


@telemetry.traced("learning.red_team")
def hunt(k: Knowledge, base: list[Scenario], *, seed: int, budget: int = 40, keep: int = 3,
         known_ids: set[str] | None = None, log: Callable[[str], None] = print) -> list[dict[str, Any]]:
    """Run up to `budget` variants against knowledge `k`; return up to `keep` diverse evasions."""
    evasions: list[dict[str, Any]] = []
    tried = 0
    used_ops: set[frozenset] = set()
    for spec in variants(base, seed):
        if known_ids and spec["id"] in known_ids:
            continue
        if tried >= budget or len(evasions) >= keep:
            break
        tried += 1
        r, _ = run_scenario(build(spec), k)
        ops = frozenset(spec["provenance"]["operators"])
        if not r.detected and not any(ops <= u or u <= ops for u in used_ops):
            used_ops.add(ops)
            spec["provenance"]["evaded_version"] = k.version
            spec["provenance"]["confidence_at_evasion"] = r.confidence
            evasions.append(spec)
            telemetry.add_event("evasion", **{"sentinel.scenario": spec["id"], "sentinel.confidence": r.confidence})
            log(f"evasion: {spec['id']} (confidence {r.confidence:.2f} < threshold {k.d['open_threshold']})")
    telemetry.annotate(**{"sentinel.knowledge_version": k.version, "sentinel.variants_tried": tried,
                          "sentinel.evasions": [e["id"] for e in evasions]})
    log(f"red team tried {tried} variants against v{k.version}: {len(evasions)} new evasion(s)")
    return evasions
