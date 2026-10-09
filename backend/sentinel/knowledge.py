"""Versioned knowledge store: detector rules, thresholds and planner playbooks the system can learn.

Guardrails, risk tiers, the policy evaluator, the executor and the evaluator's scoring are code and are never
part of the knowledge store, so learning cannot loosen them.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import config

KDIR = config.ROOT / "knowledge"
VERSIONS = KDIR / "versions"
CURRENT = KDIR / "CURRENT"
CHANGELOG = KDIR / "CHANGELOG.md"
MEMORY = KDIR / "memory" / "incidents.jsonl"
PENDING = KDIR / "pending.yaml"

FEATURES = {
    "new_network", "new_user_agent", "off_hours", "iam_read", "iam_write", "key_created", "fresh_key",
    "data_action", "first_time_resource", "critical_resource", "succeeded", "denied", "suspicious_context",
    "assumed_role",
}
SUBJECT_FIELDS = {"network", "ip", "ua", "key", "resource", "who", "principal", "action", "origin_key", "new_key"}
PLAYBOOK_CONDITIONS = {"key_in_use_by_ci", "key_minted_during_incident"}


class Knowledge:
    def __init__(self, data: dict[str, Any]) -> None:
        validate(data)
        self.d = data

    @property
    def version(self) -> int:
        return int(self.d["version"])

    @property
    def detectors(self) -> list[dict[str, Any]]:
        return [x for x in self.d["detectors"] if x.get("enabled", True)]

    @property
    def playbooks(self) -> list[dict[str, Any]]:
        return self.d.get("playbooks", [])

    def detector(self, did: str) -> dict[str, Any] | None:
        return next((x for x in self.d["detectors"] if x["id"] == did), None)

    def weight(self, did: str) -> float:
        det = self.detector(did)
        return float(det["weight"]) if det else 0.0

    def clone(self) -> Knowledge:
        return Knowledge(copy.deepcopy(self.d))

    def dump(self) -> str:
        return yaml.safe_dump(self.d, sort_keys=False, width=110)


def validate(d: dict[str, Any]) -> None:
    for k in ("version", "open_threshold", "detectors"):
        if k not in d:
            raise ValueError(f"knowledge missing '{k}'")
    if not 0.3 <= float(d["open_threshold"]) <= 0.95:
        raise ValueError("open_threshold out of bounds [0.3, 0.95]")
    ids = set()
    for det in d["detectors"]:
        if det["id"] in ids:
            raise ValueError(f"duplicate detector {det['id']}")
        ids.add(det["id"])
        if det.get("kind") not in ("rule", "burst"):
            raise ValueError(f"{det['id']}: unknown kind")
        if not 0.0 < float(det["weight"]) <= 0.6:
            raise ValueError(f"{det['id']}: weight must be in (0, 0.6]")
        feats = set(det.get("all_of", [])) | set(det.get("any_of", []))
        if not feats or not feats <= FEATURES:
            raise ValueError(f"{det['id']}: unknown features {feats - FEATURES}")
        if not set(det.get("subject", [])) <= SUBJECT_FIELDS:
            raise ValueError(f"{det['id']}: unknown subject fields")
    for pb in d.get("playbooks", []):
        if not set(pb.get("when", {}).get("conditions", [])) <= PLAYBOOK_CONDITIONS:
            raise ValueError(f"{pb.get('id')}: unknown playbook condition")


def current_version() -> int:
    return int(CURRENT.read_text().strip()) if CURRENT.exists() else 1


def load(version: int | None = None) -> Knowledge:
    v = version or current_version()
    return Knowledge(yaml.safe_load((VERSIONS / f"v{v}.yaml").read_text()))


def versions() -> list[int]:
    return sorted(int(p.stem[1:]) for p in VERSIONS.glob("v*.yaml"))


def scorecard_path(v: int) -> Path:
    return VERSIONS / f"v{v}.score.json"


def save_scorecard(v: int, card: dict[str, Any]) -> None:
    scorecard_path(v).write_text(json.dumps(card, indent=1, default=str))


def load_scorecard(v: int) -> dict[str, Any] | None:
    p = scorecard_path(v)
    return json.loads(p.read_text()) if p.exists() else None


def promote(candidate: Knowledge, *, summary: str, changes: list[dict[str, Any]], card: dict[str, Any],
            approved_by: str) -> int:
    """Write candidate as the next version, make it current, and append to the changelog."""
    new_v = max(versions()) + 1
    d = copy.deepcopy(candidate.d)
    d.update(version=new_v, parent=current_version(), created=datetime.now(timezone.utc).isoformat(),
             summary=summary)
    Knowledge(d)
    (VERSIONS / f"v{new_v}.yaml").write_text(yaml.safe_dump(d, sort_keys=False, width=110))
    save_scorecard(new_v, card)
    CURRENT.write_text(f"{new_v}\n")
    m = card.get("metrics", {})
    entry = [f"## v{new_v} — {summary}", "",
             f"- Parent: v{d['parent']} · approved by: {approved_by} · {d['created'][:19]}Z",
             f"- Scorecard: recall {m.get('recall', 0):.0%}, false positives {m.get('false_positives')}, "
             f"avg sandbox attempts {m.get('avg_attempts', 0):.2f}, avg events-to-detect "
             f"{m.get('avg_time_to_detect', 0):.1f}"]
    for c in changes:
        entry.append(f"- **{c['type']}** `{c.get('id', '')}`: {c.get('description', '')}")
        if c.get("trigger"):
            entry.append(f"  - triggered by: {c['trigger']}")
    with open(CHANGELOG, "a") as f:
        f.write("\n".join(entry) + "\n\n")
    PENDING.unlink(missing_ok=True)
    return new_v


def rollback(to_version: int) -> None:
    if to_version not in versions():
        raise ValueError(f"no such version v{to_version}")
    CURRENT.write_text(f"{to_version}\n")
    with open(CHANGELOG, "a") as f:
        f.write(f"## rollback → v{to_version} ({datetime.now(timezone.utc).isoformat()[:19]}Z)\n\n")


def changelog() -> str:
    return CHANGELOG.read_text() if CHANGELOG.exists() else ""


# ---- episodic memory -----------------------------------------------------------------------------

def remember(entry: dict[str, Any]) -> None:
    MEMORY.parent.mkdir(parents=True, exist_ok=True)
    with open(MEMORY, "a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def memories() -> list[dict[str, Any]]:
    if not MEMORY.exists():
        return []
    return [json.loads(line) for line in MEMORY.read_text().splitlines() if line.strip()]


def similar_incidents(detectors: set[str], principal: str, limit: int = 2) -> list[tuple[float, dict[str, Any]]]:
    out = []
    for m in memories():
        other = set(m.get("detectors", []))
        if not other:
            continue
        sim = len(detectors & other) / len(detectors | other)
        if m.get("principal") == principal:
            sim = min(1.0, sim + 0.1)
        out.append((round(sim, 2), m))
    return sorted(out, key=lambda x: -x[0])[:limit]
