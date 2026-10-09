"""Generates the provisioned Grafana dashboards: python observability/grafana/build_dashboards.py

Three dashboards, all backed by the same ClickHouse:
  agents.json    — OpenTelemetry traces/logs of the agent pipeline (otel.otel_traces / otel.otel_logs)
  security.json  — the CloudTrail lake (sentinel.cloudtrail)
  learning.json  — self-improvement: scorecards (sentinel.eval_results) + learning traces
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "dashboards"
DS = {"type": "grafana-clickhouse-datasource", "uid": "clickhouse"}
TIMESERIES, TABLE, LOGS, TRACE = 0, 1, 2, 3

INC = "SpanName = 'incident' AND ServiceName = 'sentinel'"
A = "SpanAttributes"
LLM = f"{A}['gen_ai.system'] = 'openai'"


def q(sql: str, fmt: int = TABLE, ref: str = "A") -> dict:
    return {"refId": ref, "datasource": DS, "editorType": "sql", "format": fmt, "rawSql": " ".join(sql.split())}


class Board:
    def __init__(self) -> None:
        self.panels: list[dict] = []
        self.y = 0
        self.x = 0
        self.row_h = 0

    def add(self, kind: str, title: str, w: int, h: int, targets: list[dict], *, unit: str | None = None,
            options: dict | None = None, defaults: dict | None = None, overrides: list | None = None,
            transformations: list | None = None, description: str = "") -> None:
        if self.x + w > 24:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        fd = {"unit": unit} if unit else {}
        fd.update(defaults or {})
        self.panels.append({
            "id": len(self.panels) + 1, "type": kind, "title": title, "description": description, "datasource": DS,
            "gridPos": {"x": self.x, "y": self.y, "w": w, "h": h}, "targets": targets,
            "fieldConfig": {"defaults": fd, "overrides": overrides or []}, "options": options or {},
            "transformations": transformations or []})
        self.x += w
        self.row_h = max(self.row_h, h)

    def row(self, title: str) -> None:
        if self.x:
            self.y += self.row_h
            self.x, self.row_h = 0, 0
        self.panels.append({"id": len(self.panels) + 1, "type": "row", "title": title, "collapsed": False,
                            "gridPos": {"x": 0, "y": self.y, "w": 24, "h": 1}, "panels": []})
        self.y += 1

    def stat(self, title: str, sql: str, unit: str | None = None, w: int = 4, color: str = "blue",
             thresholds: list | None = None, decimals: int | None = None, description: str = "") -> None:
        d = {"color": {"mode": "thresholds"},
             "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": color, "value": None}]}}
        if decimals is not None:
            d["decimals"] = decimals
        self.add("stat", title, w, 4, [q(sql)], unit=unit, defaults=d, description=description, options={
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "background", "graphMode": "none", "textMode": "value", "justifyMode": "center"})

    def table(self, title: str, sql: str, w: int, h: int, **kw) -> None:
        self.add("table", title, w, h, [q(sql)], options={"showHeader": True, "cellHeight": "sm",
                                                         "footer": {"show": False}}, **kw)

    def bars(self, title: str, sql: str, w: int, h: int, x: str, horizontal: bool = False, unit: str | None = None,
             stacking: str = "none", **kw) -> None:
        self.add("barchart", title, w, h, [q(sql)], unit=unit, defaults={"color": {"mode": "palette-classic"}},
                 options={"xField": x, "orientation": "horizontal" if horizontal else "vertical", "showValue": "auto",
                          "stacking": stacking, "legend": {"showLegend": True, "displayMode": "list",
                                                           "placement": "bottom"},
                          "xTickLabelRotation": 0, "barWidth": 0.7, "groupWidth": 0.7}, **kw)

    def series(self, title: str, sql: str, w: int, h: int, unit: str | None = None, draw: str = "line",
               stack: bool = False, **kw) -> None:
        self.add("timeseries", title, w, h, [q(sql, TIMESERIES)], unit=unit, defaults={
            "color": {"mode": "palette-classic"},
            "custom": {"drawStyle": draw, "fillOpacity": 25 if draw == "bars" else 10, "lineWidth": 2,
                       "showPoints": "auto", "stacking": {"mode": "normal" if stack else "none"}}},
            options={"legend": {"showLegend": True, "displayMode": "list", "placement": "bottom"},
                     "tooltip": {"mode": "multi"}}, **kw)


def dashboard(uid: str, title: str, board: Board, *, time: dict, refresh: str = "", variables: list | None = None,
              description: str = "", links: list | None = None) -> dict:
    return {"uid": uid, "title": title, "description": description, "tags": ["sentinel"], "timezone": "utc",
            "schemaVersion": 39, "version": 1, "editable": True, "graphTooltip": 1, "time": time,
            "refresh": refresh, "panels": board.panels, "templating": {"list": variables or []},
            "links": links or [{"title": "Sentinel dashboards", "type": "dashboards", "tags": ["sentinel"],
                                "asDropdown": False, "includeVars": False, "keepTime": False}],
            "annotations": {"list": []}}


# ---------------------------------------------------------------------------------------------------------------
# Agent observability (OpenTelemetry)
# ---------------------------------------------------------------------------------------------------------------

def agents() -> dict:
    b = Board()
    tf = "$__timeFilter(Timestamp)"
    b.row("Fleet: every autonomous incident response in the time range")
    b.stat("Incidents handled", f"SELECT count() FROM otel.otel_traces WHERE {INC} AND {tf}", color="blue")
    b.stat("Resolved autonomously", f"SELECT avg({A}['sentinel.outcome'] = 'resolved') FROM otel.otel_traces "
                                    f"WHERE {INC} AND {tf}", unit="percentunit", decimals=0,
           thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 0.8},
                       {"color": "green", "value": 0.95}])
    b.stat("Median time to verified containment",
           f"SELECT quantile(0.5)(toFloat64OrNull({A}['sentinel.time_to_contain_s'])) FROM otel.otel_traces "
           f"WHERE {INC} AND {tf}", unit="s", decimals=1, color="purple",
           description="Wall-clock seconds from incident opened to production-verified containment (includes "
                       "human approval wait when not auto-approved).")
    b.stat("Plans passing sandbox first try",
           f"SELECT avg({A}['sentinel.sandbox_first_try'] = 'true') FROM otel.otel_traces WHERE {INC} AND {tf} "
           f"AND {A}['sentinel.plan_attempts'] != ''", unit="percentunit", decimals=0,
           thresholds=[{"color": "orange", "value": None}, {"color": "green", "value": 0.99}])
    b.stat("LLM tokens", f"SELECT sum(toUInt64OrZero({A}['gen_ai.usage.input_tokens']) + "
                         f"toUInt64OrZero({A}['gen_ai.usage.output_tokens'])) FROM otel.otel_traces WHERE {LLM} "
                         f"AND {tf}", unit="short", color="semi-dark-blue")
    b.stat("LLM cost (est.)", f"SELECT sum(toFloat64OrZero({A}['sentinel.llm.cost_usd'])) FROM otel.otel_traces "
                              f"WHERE {LLM} AND {tf}", unit="currencyUSD", decimals=3, color="semi-dark-blue")

    link = [{"title": "Open this trace", "url": "/d/sentinel-agents/sentinel-agent-observability?var-trace_id="
                                                "${__data.fields.trace_id}&${__url_time_range}"}]
    b.table("Recent incidents — click a row's trace to inspect it",
            f"""SELECT Timestamp AS started, {A}['sentinel.incident_id'] AS incident, {A}['sentinel.outcome'] AS outcome,
                concat('v', {A}['sentinel.knowledge_version']) AS knowledge, {A}['sentinel.reasoning'] AS reasoning,
                toUInt8OrNull({A}['sentinel.plan_attempts']) AS sandbox_attempts,
                toFloat64OrNull({A}['sentinel.time_to_contain_s']) AS contain_s,
                concat({A}['sentinel.paths_before'], ' → ', {A}['sentinel.paths_after']) AS attack_paths,
                Duration / 1e9 AS duration_s, TraceId AS trace_id
                FROM otel.otel_traces WHERE {INC} AND {tf} ORDER BY Timestamp DESC LIMIT 50""",
            24, 8, overrides=[
                {"matcher": {"id": "byName", "options": "trace_id"}, "properties": [{"id": "links", "value": link}]},
                {"matcher": {"id": "byName", "options": "outcome"}, "properties": [
                    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                    {"id": "mappings", "value": [{"type": "value", "options": {
                        "resolved": {"color": "green", "index": 0}, "failed": {"color": "red", "index": 1},
                        "awaiting_approval": {"color": "orange", "index": 2}}}]}]},
                {"matcher": {"id": "byName", "options": "contain_s"}, "properties": [{"id": "unit", "value": "s"}]},
                {"matcher": {"id": "byName", "options": "duration_s"}, "properties": [{"id": "unit", "value": "s"}]}])

    b.row("Selected incident trace (pick one in the trace_id dropdown above)")
    b.add("traces", "Agent trace: detection → investigation → planning → sandbox → execution → verification", 24, 14,
          [q(f"""SELECT TraceId AS traceID, SpanId AS spanID, ParentSpanId AS parentSpanID, ServiceName AS serviceName,
                 SpanName AS operationName, multiply(toUnixTimestamp64Nano(Timestamp), 0.000001) AS startTime,
                 multiply(Duration, 0.000001) AS duration,
                 arrayMap(key -> map('key', key, 'value', {A}[key]), mapKeys({A})) AS tags,
                 arrayMap(key -> map('key', key, 'value', ResourceAttributes[key]), mapKeys(ResourceAttributes))
                   AS serviceTags,
                 if(StatusCode = 'Error', 2, 0) AS statusCode, StatusMessage AS statusMessage,
                 arrayMap((name, ts, attrs) -> tuple(multiply(toUnixTimestamp64Nano(ts), 0.000001),
                   map('event', name), attrs)::Tuple(timestamp Float64, fields Map(String, String),
                   attrs Map(String, String)), Events.Name, Events.Timestamp, Events.Attributes) AS logs
                 FROM otel.otel_traces WHERE TraceId = '${{trace_id}}' ORDER BY startTime""", TRACE)])
    b.bars("Where the time went (this trace)",
           f"""SELECT SpanName AS span, round(sum(Duration) / 1e6, 1) AS ms FROM otel.otel_traces
               WHERE TraceId = '${{trace_id}}' AND SpanName NOT IN ('incident') GROUP BY SpanName
               ORDER BY ms DESC LIMIT 15""", 9, 10, x="span", horizontal=True, unit="ms")
    b.table("Sandbox attempts (this trace) — ablation pins the culprit action",
            f"""SELECT {A}['sentinel.attempt'] AS attempt, if({A}['sentinel.passed'] = 'true', 'PASS', 'FAIL') AS result,
                concat({A}['sentinel.checks_failed'], '/', {A}['sentinel.checks_total']) AS failed,
                {A}['sentinel.failed_checks'] AS failed_checks, {A}['sentinel.culprits'] AS culprits,
                round(Duration / 1e6, 1) AS ms
                FROM otel.otel_traces WHERE TraceId = '${{trace_id}}' AND SpanName = 'sandbox.attempt'
                ORDER BY Timestamp""", 15, 10, overrides=[
                {"matcher": {"id": "byName", "options": "result"}, "properties": [
                    {"id": "custom.cellOptions", "value": {"type": "color-background"}},
                    {"id": "mappings", "value": [{"type": "value", "options": {
                        "PASS": {"color": "green", "index": 0}, "FAIL": {"color": "red", "index": 1}}}]}]}])
    b.add("logs", "Agent log (this trace) — every line is correlated to its span", 24, 12,
          [q("""SELECT Timestamp AS timestamp, concat('[', LogAttributes['sentinel.agent'], '] ', Body) AS body,
                lower(SeverityText) AS level, LogAttributes['sentinel.kind'] AS kind,
                LogAttributes['sentinel.sim_time'] AS sim_time, LogAttributes['sentinel.evidence_ids'] AS evidence
                FROM otel.otel_logs WHERE TraceId = '${trace_id}' ORDER BY Timestamp""", LOGS)],
          options={"showTime": True, "wrapLogMessage": True, "sortOrder": "Ascending", "enableLogDetails": True,
                   "dedupStrategy": "none", "showLabels": False})

    b.row("LLM & tools across all incidents (GenAI semantic conventions)")
    b.series("LLM latency by agent", f"""SELECT $__timeInterval(Timestamp) AS time,
               splitByChar('.', {A}['sentinel.llm.purpose'])[1] AS agent, avg(Duration) / 1e6 AS latency_ms
               FROM otel.otel_traces WHERE {LLM} AND {tf} GROUP BY time, agent ORDER BY time""", 12, 9, unit="ms",
             draw="points")
    b.bars("Tokens by agent", f"""SELECT splitByChar('.', {A}['sentinel.llm.purpose'])[1] AS agent,
             sum(toUInt64OrZero({A}['gen_ai.usage.input_tokens'])) AS input,
             sum(toUInt64OrZero({A}['gen_ai.usage.output_tokens'])) AS output
             FROM otel.otel_traces WHERE {LLM} AND {tf} GROUP BY agent ORDER BY input DESC""", 12, 9, x="agent",
           horizontal=True, stacking="normal", unit="short")
    b.table("Tool calls", f"""SELECT {A}['sentinel.tool.name'] AS tool, {A}['sentinel.tool.chosen_by'] AS chosen_by,
              count() AS calls, round(avg(Duration) / 1e6, 2) AS avg_ms, round(quantile(0.95)(Duration) / 1e6, 2) AS p95_ms,
              countIf(StatusCode = 'Error') AS errors FROM otel.otel_traces
              WHERE SpanName LIKE 'tool %' AND {tf} GROUP BY tool, chosen_by ORDER BY calls DESC""", 12, 9)
    b.table("Errors & failed spans", f"""SELECT Timestamp AS time, SpanName AS span, StatusMessage AS message,
              {A}['sentinel.incident_id'] AS incident, TraceId AS trace_id FROM otel.otel_traces
              WHERE StatusCode = 'Error' AND {tf} ORDER BY Timestamp DESC LIMIT 50""", 12, 9, overrides=[
                {"matcher": {"id": "byName", "options": "trace_id"}, "properties": [{"id": "links", "value": link}]}])

    var = {"name": "trace_id", "label": "incident trace", "type": "query", "datasource": DS, "refresh": 2,
           "query": f"SELECT TraceId AS value, concat({A}['sentinel.incident_id'], ' · ', "
                    f"formatDateTime(Timestamp, '%H:%i:%S'), ' · ', {A}['sentinel.outcome']) AS text "
                    f"FROM otel.otel_traces WHERE {INC} "
                    f"AND $__timeFilter(Timestamp) ORDER BY Timestamp DESC LIMIT 50",
           "definition": "latest incident traces", "sort": 0, "current": {}, "options": [], "hide": 0,
           "includeAll": False, "multi": False}
    return dashboard("sentinel-agents", "Sentinel · Agent observability", b, time={"from": "now-6h", "to": "now"},
                     refresh="10s", variables=[var],
                     description="OpenTelemetry traces and logs of Sentinel's agents, stored in ClickHouse.")


# ---------------------------------------------------------------------------------------------------------------
# Security: the CloudTrail lake
# ---------------------------------------------------------------------------------------------------------------

def security() -> dict:
    b = Board()
    ct = "sentinel.cloudtrail"
    tf = "$__timeFilter(time)"
    base = f"SELECT DISTINCT ip FROM {ct} WHERE source = 'baseline'"
    latest = f"(SELECT max(source) FROM {ct} WHERE source != 'baseline')"
    b.row("CloudTrail lake")
    b.stat("Baseline events (30 days)", f"SELECT count() FROM {ct} WHERE source = 'baseline'", color="blue")
    b.stat("Identities profiled", f"SELECT uniq(principal) FROM {ct} WHERE source = 'baseline'", color="blue")
    b.stat("Incident replays ingested", f"SELECT uniq(source) FROM {ct} WHERE source != 'baseline'", color="purple")
    b.stat("Never-seen source IPs", f"SELECT uniq(ip) FROM {ct} WHERE source != 'baseline' AND ip NOT IN ({base})",
           thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.stat("Denied calls (incidents)", f"SELECT countIf(error != '') FROM {ct} WHERE source = {latest}",
           thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}])
    b.stat("Distinct baseline behaviors", f"SELECT count() FROM (SELECT origin_user, ip, iam_action, "
           f"resource_family FROM {ct} WHERE source = 'baseline' GROUP BY ALL)", color="semi-dark-green",
           description="Distinct (identity, IP, action, resource) tuples — what the detectors compare against.")
    b.series("API calls per hour — baseline vs incident replay",
             f"""SELECT $__timeInterval(time) AS t, if(source = 'baseline', 'baseline (normal CI + prod)',
                 if(ip IN ({base}), 'incident window: known IPs', 'incident window: attacker IP')) AS series,
                 count() AS calls FROM {ct} WHERE {tf} AND (source = 'baseline' OR source = {latest})
                 GROUP BY t, series ORDER BY t""", 24, 9, draw="bars", stack=True, unit="short")
    b.row("Hunting: what changed vs the baseline (latest incident replay)")
    b.table("Source IPs never seen in 30 days", f"""SELECT ip, uniq(source) AS incidents,
              arrayStringConcat(groupUniqArray(principal), ', ') AS identities, count() AS calls,
              countIf(error != '') AS denied, min(time) AS first_seen, max(time) AS last_seen
              FROM {ct} WHERE source != 'baseline' AND ip NOT IN ({base}) GROUP BY ip ORDER BY calls DESC""",
            12, 7)
    b.table("Actions an identity had never performed", f"""WITH b AS (SELECT DISTINCT origin_user, iam_action FROM {ct}
              WHERE source = 'baseline') SELECT l.origin_user AS identity, l.iam_action AS action, count() AS calls,
              countIf(l.error != '') AS denied FROM {ct} AS l LEFT ANTI JOIN b USING (origin_user, iam_action)
              WHERE l.source = {latest} GROUP BY identity, action ORDER BY calls DESC""", 12, 7)
    b.table("Attacker kill chain (calls from never-seen IPs)", f"""SELECT time, event_name, principal,
              principal_type AS type, access_key, resource, if(error = '', 'ok', error) AS result, user_agent
              FROM {ct} WHERE source = {latest} AND ip NOT IN ({base}) ORDER BY time""", 24, 10, overrides=[
                {"matcher": {"id": "byName", "options": "result"}, "properties": [
                    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                    {"id": "mappings", "value": [{"type": "value", "options": {"ok": {"color": "green", "index": 0}}},
                                                 {"type": "regex", "options": {"pattern": ".+", "result": {
                                                     "color": "red", "index": 1}}}]}]}])
    b.row("Baseline behavior")
    b.bars("Hour-of-day activity by identity (baseline)", f"""SELECT toString(toHour(time)) AS hour_utc,
             countIf(origin_user = 'ci-deployer') AS ci_deployer, countIf(principal = 'prod-api-role') AS prod_api,
             countIf(origin_user = 'alice-admin') AS alice_admin FROM {ct} WHERE source = 'baseline'
             GROUP BY toHour(time) AS h, hour_utc ORDER BY h""", 12, 8, x="hour_utc", stacking="normal")
    b.table("Top actions per identity (baseline)", f"""SELECT origin_user AS identity, iam_action AS action, count() AS calls,
              uniq(ip) AS ips, uniq(resource_family) AS resources FROM {ct} WHERE source = 'baseline'
              GROUP BY identity, action ORDER BY calls DESC LIMIT 25""", 12, 8)
    return dashboard("sentinel-security", "Sentinel · CloudTrail lake", b,
                     time={"from": "2026-09-06T00:00:00.000Z", "to": "2026-10-08T00:00:00.000Z"},
                     description="CloudTrail baseline + incident replays in ClickHouse; the same tables the agents "
                                 "query for detection and hunting.")


# ---------------------------------------------------------------------------------------------------------------
# Self-improvement
# ---------------------------------------------------------------------------------------------------------------

def learning() -> dict:
    b = Board()
    ev = "sentinel.eval_results"
    b.row("Knowledge versions (scorecards recorded at each promotion)")
    b.stat("Knowledge versions", f"SELECT uniq(knowledge_version) FROM {ev}", color="purple")
    b.stat("Scenarios in latest suite", f"SELECT count() FROM {ev} WHERE knowledge_version = "
                                        f"(SELECT max(knowledge_version) FROM {ev})", color="blue")
    b.stat("Recall (latest)", f"SELECT avgIf(detected, label = 'attack') FROM {ev} WHERE knowledge_version = "
                              f"(SELECT max(knowledge_version) FROM {ev})", unit="percentunit", decimals=0,
           thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 0.999}])
    b.stat("False positives (latest)", f"SELECT countIf(detected AND label = 'benign') FROM {ev} WHERE "
                                       f"knowledge_version = (SELECT max(knowledge_version) FROM {ev})",
           thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}])
    b.stat("Candidates tested by the gate", "SELECT count() FROM otel.otel_traces WHERE SpanName = "
                                            "'learning.candidate' AND $__timeFilter(Timestamp)", color="blue")
    b.stat("Rejected for regressions", "SELECT countIf(SpanAttributes['sentinel.verdict'] = 'rejected') FROM "
                                       "otel.otel_traces WHERE SpanName = 'learning.candidate' AND "
                                       "$__timeFilter(Timestamp)", color="orange")
    b.bars("Detection quality by knowledge version", f"""SELECT concat('v', toString(knowledge_version)) AS version,
             avgIf(detected, label = 'attack') AS recall, avg(correct) AS accuracy,
             avgIf(plan_attempts = 1, detected AND label = 'attack') AS first_try_plans
             FROM {ev} GROUP BY knowledge_version ORDER BY knowledge_version""", 12, 9, x="version",
           unit="percentunit")
    b.bars("Mistakes by knowledge version", f"""SELECT concat('v', toString(knowledge_version)) AS version,
             countIf(NOT detected AND label = 'attack') AS missed_attacks,
             countIf(detected AND label = 'benign') AS false_positives,
             sumIf(plan_attempts - 1, detected AND plan_attempts > 1) AS extra_sandbox_attempts
             FROM {ev} GROUP BY knowledge_version ORDER BY knowledge_version""", 12, 9, x="version",
           stacking="normal")
    b.table("Scenario × version (✓ correct · ✗ wrong; ⚔ = discovered by the red team)",
            f"""SELECT concat(if(startsWith(scenario, 'rt-'), '⚔ ', ''), scenario, ' [', label, ']') AS scenario,
                concat('v', toString(knowledge_version)) AS version,
                if(correct, if(label = 'attack', concat('✓ ', toString(ifNull(plan_attempts, 0)), ' try'), '✓'),
                   if(label = 'attack', '✗ missed', '✗ false alarm')) AS result
                FROM {ev} ORDER BY scenario, knowledge_version
                LIMIT 1 BY scenario, knowledge_version""", 24, 11,
            transformations=[{"id": "groupingToMatrix", "options": {
                "columnField": "version", "rowField": "scenario", "valueField": "result", "emptyValue": "null"}}],
            defaults={"custom": {"cellOptions": {"type": "color-text"}}, "mappings": [
                {"type": "regex", "options": {"pattern": "✓.*", "result": {"color": "green", "index": 0}}},
                {"type": "regex", "options": {"pattern": "✗.*", "result": {"color": "red", "index": 1}}}]})
    b.row("The learning loop (OpenTelemetry traces of learner, red team and promotions)")
    b.table("Every candidate change the evaluator gate tested", """SELECT Timestamp AS time,
              SpanAttributes['sentinel.change_type'] AS type, SpanAttributes['sentinel.change'] AS change,
              SpanAttributes['sentinel.trigger'] AS triggered_by, SpanAttributes['sentinel.verdict_detail'] AS verdict,
              SpanAttributes['sentinel.recall'] AS recall, SpanAttributes['sentinel.false_positives'] AS fp
              FROM otel.otel_traces WHERE SpanName = 'learning.candidate' AND $__timeFilter(Timestamp)
              ORDER BY Timestamp DESC LIMIT 100""", 24, 10, overrides=[
                {"matcher": {"id": "byName", "options": "verdict"}, "properties": [
                    {"id": "custom.cellOptions", "value": {"type": "color-text"}},
                    {"id": "mappings", "value": [
                        {"type": "regex", "options": {"pattern": "improves", "result": {"color": "green", "index": 0}}},
                        {"type": "regex", "options": {"pattern": "rejected.*", "result": {"color": "red",
                                                                                           "index": 1}}}]}]}])
    b.table("Red-team evasions found", """SELECT Timestamp AS time, SpanAttributes['sentinel.knowledge_version'] AS
              against_version, SpanAttributes['sentinel.variants_tried'] AS variants_tried,
              SpanAttributes['sentinel.evasions'] AS evasions FROM otel.otel_traces
              WHERE SpanName = 'learning.red_team' AND $__timeFilter(Timestamp) ORDER BY Timestamp DESC""", 12, 8)
    b.table("Promotions", """SELECT Timestamp AS time, SpanAttributes['sentinel.knowledge_version'] AS version,
              SpanAttributes['sentinel.approved_by'] AS approved_by, SpanAttributes['sentinel.summary'] AS summary
              FROM otel.otel_traces WHERE SpanName = 'learning.promote' AND $__timeFilter(Timestamp)
              ORDER BY Timestamp DESC""", 12, 8)
    return dashboard("sentinel-learning", "Sentinel · Self-improvement", b, time={"from": "now-24h", "to": "now"},
                     refresh="10s", description="How knowledge versions improve, and every decision of the "
                                                "learner / red team / evaluator gate.")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, d in {"agents": agents(), "security": security(), "learning": learning()}.items():
        (OUT / f"{name}.json").write_text(json.dumps(d, indent=1, ensure_ascii=False))
        print(f"wrote {name}.json ({len(d['panels'])} panels)")
