"""Behavioral baseline store. In-memory by default; ClickHouse when CLICKHOUSE_URL is set."""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Protocol

from . import config
from .cloudtrail import Normalizer
from .models import Event

log = logging.getLogger(__name__)


def resource_family(arn: str) -> str:
    """Collapse object-level ARNs to their bucket so baselines compare like with like."""
    if arn.startswith("arn:aws:s3:::") and "/" in arn:
        return arn.split("/", 1)[0]
    return arn


@dataclass
class Profile:
    identity: str
    total: int = 0
    ips: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    actions: Counter = field(default_factory=Counter)
    resources: Counter = field(default_factory=Counter)
    hours: Counter = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def as_dict(self) -> dict:
        return {
            "identity": self.identity,
            "window_events": self.total,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "source_ips": dict(self.ips.most_common(10)),
            "user_agents": dict(self.user_agents.most_common(5)),
            "actions": dict(self.actions.most_common(20)),
            "resources": dict(self.resources.most_common(20)),
            "active_hours_utc": sorted(self.hours),
        }


def generalize_resource(arn: str) -> str:
    """Object-level S3 ARNs become bucket/* for least-privilege policy generation."""
    if arn.startswith("arn:aws:s3:::") and "/" in arn:
        return arn.split("/", 1)[0] + "/*"
    return arn


class BaselineStore(Protocol):
    name: str

    def load(self, events: Iterable[Event]) -> None: ...
    def profile(self, identity: str) -> Profile: ...
    def observed_permissions(self, principal: str) -> Counter: ...
    def count(self) -> int: ...


class MemoryStore:
    name = "in-memory"

    def __init__(self) -> None:
        self._profiles: dict[str, Profile] = defaultdict(lambda: Profile(identity=""))
        self._direct: dict[str, Counter] = defaultdict(Counter)
        self._count = 0

    def observed_permissions(self, principal: str) -> Counter:
        return self._direct.get(principal, Counter())

    def load(self, events: Iterable[Event]) -> None:
        for e in events:
            self._count += 1
            if e.succeeded:
                self._direct[e.principal][(e.iam_action, generalize_resource(e.resource))] += 1
            for who in {e.principal, e.origin_user} - {None}:
                p = self._profiles[who]
                p.identity = who
                p.total += 1
                p.ips[e.ip] += 1
                p.user_agents[e.user_agent] += 1
                p.actions[e.iam_action] += 1
                p.resources[resource_family(e.resource)] += 1
                p.hours[e.time.hour] += 1
                p.first_seen = min(p.first_seen or e.time, e.time)
                p.last_seen = max(p.last_seen or e.time, e.time)

    def profile(self, identity: str) -> Profile:
        return self._profiles.get(identity) or Profile(identity=identity)

    def count(self) -> int:
        return self._count


class ClickHouseStore:
    name = "ClickHouse"
    TABLE = "sentinel_cloudtrail"

    def __init__(self, url: str) -> None:
        import clickhouse_connect

        self.client = clickhouse_connect.get_client(dsn=url)
        self.client.command(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                event_id String, time DateTime64(3, 'UTC'), principal LowCardinality(String),
                origin_user LowCardinality(String), iam_action LowCardinality(String), resource String,
                resource_family LowCardinality(String), ip String, user_agent String, error String
            ) ENGINE = MergeTree ORDER BY (origin_user, principal, time)""")

    def load(self, events: Iterable[Event]) -> None:
        self.client.command(f"TRUNCATE TABLE {self.TABLE}")
        rows = [[e.id, e.time, e.principal, e.origin_user or "", e.iam_action, e.resource,
                 resource_family(e.resource), e.ip, e.user_agent, e.error or ""] for e in events]
        cols = ["event_id", "time", "principal", "origin_user", "iam_action", "resource", "resource_family", "ip",
                "user_agent", "error"]
        for i in range(0, len(rows), 50_000):
            self.client.insert(self.TABLE, rows[i:i + 50_000], column_names=cols)

    def _counter(self, col: str, identity: str, limit: int = 20) -> Counter:
        q = (f"SELECT {col}, count() c FROM {self.TABLE} WHERE principal = %(w)s OR origin_user = %(w)s "
             f"GROUP BY {col} ORDER BY c DESC LIMIT {limit}")
        return Counter({r[0]: r[1] for r in self.client.query(q, parameters={"w": identity}).result_rows})

    def profile(self, identity: str) -> Profile:
        row = self.client.query(
            f"SELECT count(), min(time), max(time) FROM {self.TABLE} WHERE principal = %(w)s OR origin_user = %(w)s",
            parameters={"w": identity}).result_rows[0]
        if not row[0]:
            return Profile(identity=identity)
        return Profile(identity=identity, total=row[0], first_seen=row[1], last_seen=row[2],
                       ips=self._counter("ip", identity), user_agents=self._counter("user_agent", identity, 5),
                       actions=self._counter("iam_action", identity),
                       resources=self._counter("resource_family", identity),
                       hours=self._counter("toHour(time)", identity, 24))

    def observed_permissions(self, principal: str) -> Counter:
        q = (f"SELECT iam_action, resource, count() FROM {self.TABLE} WHERE principal = %(w)s AND error = '' "
             f"GROUP BY iam_action, resource")
        out: Counter = Counter()
        for action, resource, c in self.client.query(q, parameters={"w": principal}).result_rows:
            out[(action, generalize_resource(resource))] += c
        return out

    def count(self) -> int:
        return self.client.query(f"SELECT count() FROM {self.TABLE}").result_rows[0][0]


def load_baseline_events() -> list[Event]:
    path = config.FIXTURES / "baseline_events.jsonl"
    if not path.exists():
        import subprocess
        import sys

        subprocess.run([sys.executable, str(config.SCENARIO_DIR / "generate_fixtures.py")], check=True)
    norm = Normalizer()
    with open(path) as f:
        return [norm(json.loads(line)) for line in f]


_store: BaselineStore | None = None


def get_store() -> BaselineStore:
    global _store
    if _store is None:
        store: BaselineStore = MemoryStore()
        if config.CLICKHOUSE_URL:
            try:
                store = ClickHouseStore(config.CLICKHOUSE_URL)
            except Exception as exc:  # noqa: BLE001
                log.warning("ClickHouse unavailable (%s); falling back to in-memory baseline", exc)
        store.load(load_baseline_events())
        _store = store
    return _store
