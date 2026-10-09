"""Deterministic detectors. Each fires at most once per subject and cites the events that triggered it.

Confidence is a noisy-OR over distinct detectors that fired for an identity, so it is explainable:
1 - prod(1 - weight_i).
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .cloudtrail import short_resource
from .iam import IamState
from .models import Event, Signal
from .store import BaselineStore, resource_family

DATA_ACTIONS = {"s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"}

WEIGHTS = {
    "new_source_network": (0.30, 6),
    "new_user_agent": (0.20, 4),
    "rapid_iam_enumeration": (0.35, 7),
    "access_key_created": (0.40, 8),
    "fresh_key_usage": (0.30, 7),
    "first_time_resource_access": (0.25, 6),
    "sensitive_resource_access": (0.35, 8),
    "access_denied_sensitive": (0.20, 6),
}

OPEN_THRESHOLD = 0.6


def network(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/16", strict=False))
    except ValueError:
        return ip


def ua_family(ua: str) -> str:
    head = ua.split(" ")[0].split("/")[0]
    os_hint = next((p for p in ua.split(" ") if p.lower().startswith(("linux", "os/", "darwin"))), "")
    return f"{head} {os_hint.split('#')[0]}".strip()


@dataclass
class IdentityState:
    signals: list[Signal] = field(default_factory=list)
    fired: set[tuple] = field(default_factory=set)
    iam_reads: list[Event] = field(default_factory=list)
    denials: list[Event] = field(default_factory=list)

    @property
    def score(self) -> float:
        p = 1.0
        for d in {s.detector for s in self.signals}:
            p *= 1 - WEIGHTS[d][0]
        return round(1 - p, 3)


class DetectionEngine:
    def __init__(self, store: BaselineStore, iam: IamState) -> None:
        self.store = store
        self.iam = iam
        self.ids: dict[str, IdentityState] = defaultdict(IdentityState)
        self.minted_keys: dict[str, tuple[Event, str]] = {}  # key -> (create event, minting caller key)
        self.suspicious_networks: dict[str, set[str]] = defaultdict(set)
        self.suspicious_keys: set[str] = set()
        self.critical = {r["arn"]: r for r in iam.resources if r["critical"]}

    def _fire(self, who: str, detector: str, subject: str, title: str, events: list[Event]) -> Signal | None:
        st = self.ids[who]
        if (detector, subject) in st.fired:
            return None
        st.fired.add((detector, subject))
        w, sev = WEIGHTS[detector]
        sig = Signal(detector=detector, title=title, severity=sev, weight=w,
                     evidence_ids=[e.evidence_id for e in events if e.evidence_id], timestamp=events[-1].time)
        st.signals.append(sig)
        return sig

    def observe(self, e: Event) -> list[Signal]:
        who = e.origin_user or e.principal
        if who in self.iam.d.get("admins", []):
            return []
        out: list[Signal] = []
        prof = self.store.profile(who)
        net = network(e.ip)

        def fire(*a):
            s = self._fire(who, *a)
            if s:
                out.append(s)

        if prof.total and net not in {network(ip) for ip in prof.ips}:
            self.suspicious_networks[who].add(net)
            fire("new_source_network", net, f"{who} active from never-seen network {net} ({e.ip})", [e])
        if prof.total and ua_family(e.user_agent) not in {ua_family(u) for u in prof.user_agents}:
            fire("new_user_agent", ua_family(e.user_agent),
                 f"Unfamiliar client for {who}: {e.user_agent.split(' ')[0]}", [e])

        # Keys/sessions minted from a suspicious context are attacker-controlled everywhere; the original leaked
        # key is shared with legitimate CI, so its activity is attributed by source network instead.
        from_suspicious = net in self.suspicious_networks[who] or e.access_key in self.suspicious_keys

        if e.source == "iam" and e.name.startswith(("List", "Get")):
            st = self.ids[who]
            st.iam_reads.append(e)
            burst = [x for x in st.iam_reads if e.time - x.time <= timedelta(seconds=120)]
            if len(burst) >= 3:
                fire("rapid_iam_enumeration", "burst",
                     f"{len(burst)} IAM discovery calls in {(e.time - burst[0].time).seconds}s by {who}", burst)

        if e.iam_action == "iam:CreateAccessKey" and e.succeeded:
            new_key = ((e.raw.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId")
            if new_key:
                self.minted_keys[new_key] = (e, e.access_key)
                if from_suspicious:
                    self.suspicious_keys.add(new_key)
                fire("access_key_created", new_key, f"New long-lived access key {new_key} created for {who}", [e])

        if e.name == "AssumeRole" and e.succeeded and from_suspicious:
            sk = ((e.raw.get("responseElements") or {}).get("credentials") or {}).get("accessKeyId")
            if sk:
                self.suspicious_keys.add(sk)

        origin = e.origin_key or e.access_key
        if origin in self.minted_keys:
            created, _ = self.minted_keys[origin]
            if e.time - created.time <= timedelta(minutes=10) and e.id != created.id:
                fire("fresh_key_usage", origin,
                     f"Key {origin} used {int((e.time - created.time).total_seconds())}s after creation "
                     f"({e.name})", [created, e])

        fam = resource_family(e.resource)
        if e.iam_action in DATA_ACTIONS:
            known = set(prof.resources) | set(self.store.profile(e.principal).resources)
            first_time = fam not in known
            if first_time:
                fire("first_time_resource_access", fam,
                     f"{e.principal} accessed {short_resource(fam)} for the first time in 30 days", [e])
            if fam in self.critical and (first_time or from_suspicious) and e.succeeded:
                fire("sensitive_resource_access", f"{e.access_key}:{fam}",
                     f"Critical asset {short_resource(fam)} read via {e.access_key[:4]}…{e.access_key[-4:]} "
                     f"from {e.ip}", [e])

        if e.error and e.error.startswith("AccessDenied"):
            st = self.ids[who]
            st.denials.append(e)
            if fam in self.critical or len(st.denials) >= 3:
                fire("access_denied_sensitive", fam, f"Denied attempt on {short_resource(fam)} by {e.principal}", [e])
        return out

    def score(self, who: str) -> float:
        return self.ids[who].score

    def is_attacker_event(self, who: str, e: Event) -> bool:
        if (e.origin_user or e.principal) != who:
            return False
        return network(e.ip) in self.suspicious_networks[who] or e.access_key in self.suspicious_keys
