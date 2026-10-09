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
    supports_sql: bool

    def load(self, events: Iterable[Event]) -> None: ...
    def profile(self, identity: str) -> Profile: ...
    def observed_permissions(self, principal: str) -> Counter: ...
    def count(self) -> int: ...
    def ingest(self, run_id: str, events: list[Event]) -> None: ...
    def sql(self, query: str) -> dict: ...
    def record_eval(self, version: int, results: list[dict]) -> None: ...


class MemoryStore:
    name = "in-memory"
    supports_sql = False

    def ingest(self, run_id: str, events: list[Event]) -> None:
        pass

    def sql(self, query: str) -> dict:
        raise RuntimeError("SQL hunting requires ClickHouse (set CLICKHOUSE_URL)")

    def record_eval(self, version: int, results: list[dict]) -> None:
        pass

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
    """CloudTrail lake in ClickHouse.

    `cloudtrail` holds the 30-day baseline (source='baseline') plus every live incident replay (source=<run id>);
    baseline profiles only ever read source='baseline'. `eval_results` keeps every scorecard row so knowledge
    versions can be compared with SQL. Agent SQL runs read-only and row/time limits."""

    name = "ClickHouse"
    supports_sql = True
    TABLE = "cloudtrail"
    EVAL_TABLE = "eval_results"
    COLS = ["source", "event_id", "time", "event_name", "event_source", "principal", "principal_type", "origin_user",
            "access_key", "origin_key", "iam_action", "resource", "resource_family", "ip", "user_agent", "error",
            "read_only"]
    BASE = "source = 'baseline'"
    WHO = "(principal = %(w)s OR origin_user = %(w)s)"

    def __init__(self, url: str) -> None:
        import clickhouse_connect

        self.client = clickhouse_connect.get_client(dsn=url, connect_timeout=3, autogenerate_session_id=False)
        self._profiles: dict[str, Profile] = {}
        self._perms: dict[str, Counter] = {}
        self._count: int | None = None
        self.client.command(f"""
            CREATE TABLE IF NOT EXISTS {self.TABLE} (
                source LowCardinality(String), event_id String, time DateTime64(3, 'UTC'),
                event_name LowCardinality(String), event_source LowCardinality(String),
                principal LowCardinality(String), principal_type LowCardinality(String),
                origin_user LowCardinality(String), access_key String, origin_key String,
                iam_action LowCardinality(String), resource String, resource_family LowCardinality(String),
                ip String, user_agent String, error LowCardinality(String), read_only Bool,
                ingested_at DateTime64(3, 'UTC') DEFAULT now64(3)
            ) ENGINE = MergeTree ORDER BY (source, origin_user, principal, time)""")
        self.client.command(f"""
            CREATE TABLE IF NOT EXISTS {self.EVAL_TABLE} (
                evaluated_at DateTime64(3, 'UTC') DEFAULT now64(3), knowledge_version UInt32,
                scenario LowCardinality(String), label LowCardinality(String), detected Bool, correct Bool,
                confidence Float32, events_to_detect Nullable(UInt32), plan_attempts Nullable(UInt32),
                contained Bool, detectors Array(String)
            ) ENGINE = MergeTree ORDER BY (knowledge_version, scenario, evaluated_at)""")

    @staticmethod
    def _row(source: str, e: Event) -> list:
        return [source, e.id, e.time, e.name, e.source, e.principal, e.principal_type or "", e.origin_user or "",
                e.access_key or "", e.origin_key or "", e.iam_action, e.resource, resource_family(e.resource), e.ip,
                e.user_agent, e.error or "", bool(e.raw.get("readOnly", True))]

    def load(self, events: Iterable[Event]) -> None:
        events = list(events)
        have = self.client.query(f"SELECT count() FROM {self.TABLE} WHERE {self.BASE}").result_rows[0][0]
        if have == len(events):
            log.info("ClickHouse baseline already loaded (%d events)", have)
            return
        self.client.command(f"ALTER TABLE {self.TABLE} DELETE WHERE {self.BASE} SETTINGS mutations_sync = 1")
        rows = [self._row("baseline", e) for e in events]
        for i in range(0, len(rows), 50_000):
            self.client.insert(self.TABLE, rows[i:i + 50_000], column_names=self.COLS)
        log.info("Loaded %d baseline events into ClickHouse", len(rows))

    def ingest(self, run_id: str, events: list[Event]) -> None:
        if events:
            self.client.insert(self.TABLE, [self._row(run_id, e) for e in events], column_names=self.COLS)

    def _counter(self, col: str, identity: str) -> Counter:
        q = (f"SELECT {col}, count() c FROM {self.TABLE} WHERE {self.BASE} AND {self.WHO} "
             f"GROUP BY {col} ORDER BY c DESC")
        return Counter({r[0]: r[1] for r in self.client.query(q, parameters={"w": identity}).result_rows})

    def profile(self, identity: str) -> Profile:
        if identity in self._profiles:
            return self._profiles[identity]
        row = self.client.query(
            f"SELECT count(), min(time), max(time) FROM {self.TABLE} WHERE {self.BASE} AND {self.WHO}",
            parameters={"w": identity}).result_rows[0]
        if not row[0]:
            prof = Profile(identity=identity)
        else:
            prof = Profile(identity=identity, total=row[0], first_seen=row[1], last_seen=row[2],
                           ips=self._counter("ip", identity), user_agents=self._counter("user_agent", identity),
                           actions=self._counter("iam_action", identity),
                           resources=self._counter("resource_family", identity),
                           hours=self._counter("toHour(time)", identity))
        self._profiles[identity] = prof
        return prof

    def observed_permissions(self, principal: str) -> Counter:
        if principal not in self._perms:
            q = (f"SELECT iam_action, resource, count() FROM {self.TABLE} WHERE {self.BASE} AND principal = %(w)s "
                 f"AND error = '' GROUP BY iam_action, resource")
            out: Counter = Counter()
            for action, resource, c in self.client.query(q, parameters={"w": principal}).result_rows:
                out[(action, generalize_resource(resource))] += c
            self._perms[principal] = out
        return self._perms[principal]

    def count(self) -> int:
        if self._count is None:
            self._count = self.client.query(f"SELECT count() FROM {self.TABLE} WHERE {self.BASE}").result_rows[0][0]
        return self._count

    def sql(self, query: str, parameters: dict | None = None, max_rows: int = 200) -> dict:
        q = query.strip().rstrip(";")
        if not q.lower().startswith(("select", "with")) or ";" in q:
            raise ValueError("only a single SELECT/WITH query is allowed")
        res = self.client.query(q, parameters=parameters, settings={
            "readonly": 2, "max_execution_time": 5, "max_result_rows": max_rows, "result_overflow_mode": "break"})
        rows = [[v.isoformat() if isinstance(v, datetime) else v for v in r] for r in res.result_rows[:max_rows]]
        return {"columns": list(res.column_names), "rows": rows, "row_count": len(rows)}

    def record_eval(self, version: int, results: list[dict]) -> None:
        cols = ["knowledge_version", "scenario", "label", "detected", "correct", "confidence", "events_to_detect",
                "plan_attempts", "contained", "detectors"]
        rows = [[version, r["id"], r["label"], r["detected"], r["correct"], float(r["confidence"]),
                 r.get("events_to_detect"), r.get("plan_attempts"), bool(r.get("contained")),
                 list(r.get("detectors_fired") or [])] for r in results]
        if rows:
            self.client.insert(self.EVAL_TABLE, rows, column_names=cols)


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
