"""Rule-driven detection. Every event gets a set of deterministic features; detectors (from the knowledge
store) are feature combinations that fire at most once per subject and cite the events that triggered them.

Confidence is a noisy-OR over distinct detectors that fired for an identity: 1 - prod(1 - weight_i).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .cloudtrail import short_resource
from .iam import IamState
from .knowledge import Knowledge
from .models import Event, Signal
from .store import BaselineStore, resource_family

DATA_ACTIONS = {"s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"}


def network(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/16", strict=False))
    except ValueError:
        return ip


def ua_family(ua: str) -> str:
    head = ua.split(" ")[0].split("/")[0]
    os_hint = next((p for p in ua.split(" ") if p.lower().startswith(("linux", "os/", "darwin"))), "")
    return f"{head} {os_hint.split('#')[0]}".strip()


class _Fmt(dict):
    def __missing__(self, k: str) -> str:
        return "{" + k + "}"


@dataclass
class IdentityState:
    signals: list[Signal] = field(default_factory=list)
    fired: set[tuple] = field(default_factory=set)
    bursts: dict[str, list[Event]] = field(default_factory=lambda: defaultdict(list))

    def score(self, k: Knowledge) -> float:
        p = 1.0
        for d in {s.detector for s in self.signals}:
            p *= 1 - k.weight(d)
        return round(1 - p, 3)


class DetectionEngine:
    def __init__(self, store: BaselineStore, iam: IamState, knowledge: Knowledge) -> None:
        self.store = store
        self.iam = iam
        self.k = knowledge
        self.ids: dict[str, IdentityState] = defaultdict(IdentityState)
        self.minted_keys: dict[str, Event] = {}
        self.suspicious_networks: dict[str, set[str]] = defaultdict(set)
        self.suspicious_keys: set[str] = set()
        self.tainted: set[str] = set()
        self.critical = {r["arn"]: r for r in iam.resources if r["critical"]}
        self.features_log: list[tuple[Event, set[str]]] = []

    # ---- features -------------------------------------------------------------------------------

    def features(self, e: Event, who: str) -> tuple[set[str], dict[str, Any]]:
        prof = self.store.profile(who)
        net, fam = network(e.ip), resource_family(e.resource)
        f: set[str] = set()
        if prof.total and net not in {network(ip) for ip in prof.ips}:
            f.add("new_network")
            self.suspicious_networks[who].add(net)
        if prof.total and ua_family(e.user_agent) not in {ua_family(u) for u in prof.user_agents}:
            f.add("new_user_agent")
        if prof.total and prof.hours and e.time.hour not in prof.hours:
            f.add("off_hours")
        if e.source == "iam" and e.name.startswith(("List", "Get")):
            f.add("iam_read")
        if e.source == "iam" and not e.raw.get("readOnly", True):
            f.add("iam_write")
        f.add("succeeded" if e.succeeded else "denied" if (e.error or "").startswith("AccessDenied") else "error")
        if e.principal_type == "AssumedRole":
            f.add("assumed_role")
        if fam in self.critical:
            f.add("critical_resource")
        if e.iam_action in DATA_ACTIONS:
            f.add("data_action")
            known = set(prof.resources) | set(self.store.profile(e.principal).resources)
            if fam not in known:
                f.add("first_time_resource")
        if net in self.suspicious_networks[who] or e.access_key in self.suspicious_keys:
            f.add("suspicious_context")

        fields: dict[str, Any] = {
            "who": who, "principal": e.principal, "network": net, "ip": e.ip,
            "ua": e.user_agent.split(" ")[0], "key": f"{e.access_key[:4]}…{e.access_key[-4:]}",
            "resource": short_resource(fam), "action": e.name, "origin_key": e.origin_key or e.access_key,
        }
        if e.iam_action == "iam:CreateAccessKey" and e.succeeded:
            new_key = ((e.raw.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
            if new_key:
                f.add("key_created")
                fields["new_key"] = new_key
                self.minted_keys[new_key] = e
                if "suspicious_context" in f:
                    self.suspicious_keys.add(new_key)
        origin = e.origin_key or e.access_key
        if origin in self.minted_keys and self.minted_keys[origin].id != e.id:
            age = (e.time - self.minted_keys[origin].time).total_seconds()
            if age <= 600:
                f.add("fresh_key")
                fields["age"] = int(age)
        if e.name == "AssumeRole" and e.succeeded and "suspicious_context" in f:
            sk = ((e.raw.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId")
            if sk:
                self.suspicious_keys.add(sk)
        return f, fields

    # ---- detection ------------------------------------------------------------------------------

    def _fire(self, who: str, det: dict, subject: tuple, fields: dict, events: list[Event]) -> Signal | None:
        st = self.ids[who]
        if (det["id"], subject) in st.fired:
            return None
        st.fired.add((det["id"], subject))
        sig = Signal(detector=det["id"], title=det.get("title", det["id"]).format_map(_Fmt(fields)),
                     severity=int(det.get("severity", 5)), weight=float(det["weight"]),
                     evidence_ids=[e.evidence_id for e in events if e.evidence_id], timestamp=events[-1].time)
        st.signals.append(sig)
        return sig

    def observe(self, e: Event) -> list[Signal]:
        who = e.origin_user or e.principal
        if who in self.iam.d.get("admins", []):
            return []
        feats, fields = self.features(e, who)
        self.features_log.append((e, feats))
        out: list[Signal] = []
        st = self.ids[who]
        for det in self.k.detectors:
            if not set(det.get("all_of", [])) <= feats:
                continue
            if det.get("any_of") and not set(det["any_of"]) & feats:
                continue
            subject = tuple(fields.get(s) for s in det.get("subject", []))
            events = [e]
            if det["kind"] == "burst":
                buf = st.bursts[det["id"]]
                buf.append(e)
                window = timedelta(seconds=float(det.get("window_s", 120)))
                events = [x for x in buf if e.time - x.time <= window]
                if len(events) < int(det.get("min_count", 3)):
                    continue
                fields = {**fields, "n": len(events), "secs": int((e.time - events[0].time).total_seconds())}
            s = self._fire(who, det, subject, fields, events)
            if s:
                out.append(s)
        if out:
            self.tainted.add(e.id)
            if e.access_key.startswith("ASIA") or e.access_key in self.minted_keys:
                self.suspicious_keys.add(e.access_key)
        return out

    def score(self, who: str) -> float:
        return self.ids[who].score(self.k)

    def is_attacker_event(self, who: str, e: Event) -> bool:
        if (e.origin_user or e.principal) != who:
            return False
        if network(e.ip) in self.suspicious_networks[who] or e.access_key in self.suspicious_keys or e.id in self.tainted:
            return True
        if e.name == "AssumeRole" and e.succeeded:
            sk = ((e.raw.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId")
            return sk in self.suspicious_keys
        return False
