"""Specialist agents. Each reads shared incident state, does deterministic work, optionally asks the LLM to
reason over the results, and writes structured output back. LLM output is validated: evidence IDs must exist,
action kinds/params must be in the catalog, and risk tiers / confidences are always computed in code."""

from __future__ import annotations

import json
import math
from collections import Counter, OrderedDict
from datetime import datetime, timedelta
from typing import Any

from . import config
from . import knowledge as kb
from .actions import CATALOG, Executor, risk_for, target_for, title_for, validate
from .cloudtrail import parse_time, short_resource
from .detectors import network, ua_family
from .graph import attack_paths, build_graph, diff_graph
from .integrations import lookup_ip, scan_ci_repo
from .models import Action, BlastRadius, Claim, Event, Hypothesis, TimelineEntry
from .run import Run
from .store import resource_family
from .verification import run_suite


def _claims(run: Run, raw: list[dict] | None) -> list[Claim]:
    out = []
    for c in raw or []:
        ids = run.valid_ids([str(i) for i in c.get("evidence_ids", [])])
        if c.get("text") and (ids or not c.get("evidence_ids")):
            out.append(Claim(text=c["text"], evidence_ids=ids))
    return out


def _brief_events(events: list[Event]) -> list[dict[str, Any]]:
    return [{"evidence_id": e.evidence_id, "time": e.time.strftime("%H:%M:%S"), "action": e.iam_action,
             "resource": short_resource(e.resource), "ip": e.ip, "key": e.access_key, "error": e.error}
            for e in events]


# ================================================================================================
# Investigator
# ================================================================================================

class Investigator:
    NAME = "Investigator"

    def __init__(self, run: Run) -> None:
        self.run = run
        self.facts: dict[str, Any] = {}
        self.cache: dict[str, Any] = {}

    # ---- tools (deterministic; every result is registered as evidence) --------------------------

    def baseline_profile(self, identity: str) -> dict[str, Any]:
        if f"baseline:{identity}" in self.cache:
            return self.cache[f"baseline:{identity}"]
        prof = self.run.store.profile(identity).as_dict()
        eid = self.run.add_evidence(
            "baseline", f"30-day behavior baseline for {identity}: {prof['window_events']} events, "
                        f"{len(prof['source_ips'])} source IPs, {len(prof['resources'])} resources", prof)
        out = {"evidence_id": eid, **prof}
        self.cache[f"baseline:{identity}"] = out
        self.facts.setdefault("baselines", {})[identity] = out
        return out

    def principal_activity(self, identity: str, suspicious_only: bool = False) -> dict[str, Any]:
        evs = [e for e in self.run.events if identity in (e.principal, e.origin_user)]
        if suspicious_only:
            evs = [e for e in evs if self.run.engine.is_attacker_event(self.run.incident.principal, e)]
        return {"identity": identity, "events": _brief_events(evs)}

    def iam_changes(self) -> dict[str, Any]:
        evs = [e for e in self.run.events if e.source == "iam" and not e.raw.get("readOnly", True)]
        return {"changes": _brief_events(evs)}

    def deployments(self) -> dict[str, Any]:
        if "deployments" in self.cache:
            return self.cache["deployments"]
        deploys = json.loads((config.FIXTURES / "deployments.json").read_text())
        atk = self.run.attacker_events()
        lo, hi = atk[0].time - timedelta(hours=6), atk[-1].time
        recent = [d for d in deploys if lo <= parse_time(d["time"]) <= hi]
        eid = self.run.add_evidence("deployments", f"Deploy log {lo:%H:%M}–{hi:%H:%M}: {len(recent)} deployment(s)",
                                    recent)
        out = {"evidence_id": eid, "deployments": recent}
        self.cache["deployments"] = out
        self.facts["deployments"] = recent
        self.facts["deployments_eid"] = eid
        return out

    def threat_intel(self, ip: str) -> dict[str, Any]:
        key = f"intel:{ip}"
        if key in self.cache:
            return self.cache[key]
        info = lookup_ip(ip)
        eid = self.run.add_evidence(
            "threat_intel", f"Threat intel {ip}: {info.get('org') or 'unknown org'}, category "
                            f"{info.get('category')}, blocklists: {', '.join(info.get('blocklists') or []) or 'none'}",
            info)
        out = {"evidence_id": eid, **info}
        self.cache[key] = out
        self.facts.setdefault("intel", {})[ip] = out
        return out

    def scan_ci_repo(self) -> dict[str, Any]:
        if "semgrep" in self.cache:
            return self.cache["semgrep"]
        findings = scan_ci_repo()
        ids = []
        for f in findings:
            ids.append(self.run.add_evidence(
                "semgrep", f"Semgrep {f['severity']}: {f['message']} ({f['path']}:{f['line']})", f))
        out = {"findings": [{"evidence_id": i, **f} for i, f in zip(ids, findings)]}
        self.cache["semgrep"] = out
        self.facts["semgrep"] = out["findings"]
        return out

    def hunt_sql(self, query: str, purpose: str = "") -> dict[str, Any]:
        try:
            res = self.run.store.sql(query)
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}
        eid = self.run.add_evidence("clickhouse", f"ClickHouse hunt{': ' + purpose if purpose else ''} — "
                                                  f"{res['row_count']} row(s)", {"query": query, **res})
        return {"evidence_id": eid, **res}

    def account_wide_hunt(self) -> dict[str, Any]:
        """Where else have the attacker's IPs appeared: any identity in the baseline, or earlier incident replays."""
        if "hunt" in self.cache:
            return self.cache["hunt"]
        inc, store = self.run.incident, self.run.store
        q = (f"SELECT source, principal, ip, count() AS events, min(time) AS first_seen, max(time) AS last_seen "
             f"FROM {store.TABLE} WHERE ip IN %(ips)s AND source != %(run)s "
             f"GROUP BY source, principal, ip ORDER BY first_seen")
        res = store.sql(q, {"ips": list(inc.attacker_ips), "run": self.run.run_dir.name if self.run.run_dir else ""})
        rows = [dict(zip(res["columns"], r)) for r in res["rows"]]
        base = [r for r in rows if r["source"] == "baseline"]
        prior = sorted({r["source"] for r in rows if r["source"] != "baseline"})
        eid = self.run.add_evidence(
            "clickhouse", f"ClickHouse account-wide hunt for {', '.join(inc.attacker_ips)}: "
                          f"{len(base)} baseline match(es) across {store.count():,} events, "
                          f"{len(prior)} earlier incident replay(s)", {"query": q, "rows": rows})
        out = {"evidence_id": eid, "baseline_matches": base, "prior_runs": prior}
        self.cache["hunt"] = out
        return out

    def _hunt_claim(self) -> Claim | None:
        h = self.cache.get("hunt")
        if not h:
            return None
        ips = ", ".join(self.run.incident.attacker_ips)
        if h["baseline_matches"]:
            who = sorted({r["principal"] for r in h["baseline_matches"]})
            text = f"ClickHouse: {ips} previously used by {', '.join(who)} in the 30-day baseline"
        else:
            text = (f"ClickHouse: {ips} never appears in 30 days of account-wide CloudTrail "
                    f"({self.run.store.count():,} events, all identities)")
        if h["prior_runs"]:
            text += f"; also seen in {len(h['prior_runs'])} earlier incident replay(s)"
        return Claim(text=text, evidence_ids=[h["evidence_id"]])

    TOOL_SPECS = {
        "baseline_profile": {"description": "30-day behavioral baseline (source IPs, user agents, actions, "
                                            "resources) for an IAM user or role.",
                             "parameters": {"type": "object", "properties": {"identity": {"type": "string"}},
                                            "required": ["identity"]}},
        "principal_activity": {"description": "CloudTrail events in the incident window for an identity.",
                               "parameters": {"type": "object", "properties": {
                                   "identity": {"type": "string"},
                                   "suspicious_only": {"type": "boolean"}}, "required": ["identity"]}},
        "iam_changes": {"description": "IAM write operations in the incident window.",
                        "parameters": {"type": "object", "properties": {}}},
        "deployments": {"description": "Deployments / change tickets around the incident window.",
                        "parameters": {"type": "object", "properties": {}}},
        "threat_intel": {"description": "Reputation, ASN and blocklist status for an IP.",
                         "parameters": {"type": "object", "properties": {"ip": {"type": "string"}},
                                        "required": ["ip"]}},
        "scan_ci_repo": {"description": "Run Semgrep on the CI repository that uses the compromised credential.",
                         "parameters": {"type": "object", "properties": {}}},
    }

    def _recall(self) -> Claim | None:
        inc = self.run.incident
        matches = [m for m in kb.similar_incidents({s.detector for s in inc.signals}, inc.principal) if m[0] >= 0.5]
        if not matches:
            return None
        sim, m = matches[0]
        eid = self.run.add_evidence(
            "memory", f"Past incident {m['incident_id']} ({m['date'][:10]}, similarity {sim:.0%}): {m['root_cause']}; "
                      f"resolved with {', '.join(m['final_actions'][:4])}", m)
        self.run.log(self.NAME, "tool", f"recall_similar_incidents() → {m['incident_id']} ({sim:.0%} similar)",
                     {"evidence_id": eid})
        return Claim(text=f"Matches the pattern of past incident {m['incident_id']} ({sim:.0%} similar), root cause: "
                          f"{m['root_cause']}", evidence_ids=[eid])

    SQL_SPEC = {
        "description": "Read-only ClickHouse SQL over the CloudTrail lake. Table `cloudtrail` columns: source "
                       "('baseline' = 30-day history, otherwise an incident replay id), event_id, time, event_name, "
                       "event_source, principal, principal_type, origin_user, access_key, origin_key, iam_action, "
                       "resource, resource_family, ip, user_agent, error ('' when succeeded), read_only. "
                       "Single SELECT only; max 200 rows.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"},
                                                         "purpose": {"type": "string"}}, "required": ["query"]}}

    def _tools(self):
        specs = dict(self.TOOL_SPECS)
        if self.run.store.supports_sql:
            specs["hunt_sql"] = self.SQL_SPEC
        return {n: (spec, getattr(self, n)) for n, spec in specs.items()}

    def _on_tool(self, name: str, args: dict, result: Any) -> None:
        arg = ", ".join(f"{k}={v}" for k, v in args.items())
        self.run.log(self.NAME, "tool", f"{name}({arg})", {"evidence_id": (result or {}).get("evidence_id")}
                     if isinstance(result, dict) else None)

    def _gather_required(self) -> None:
        inc = self.run.incident
        role = next(iter({e.principal for e in self.run.attacker_events() if e.principal_type == "AssumedRole"}), None)
        required = [("baseline_profile", {"identity": inc.principal}),
                    *([("baseline_profile", {"identity": role})] if role else []),
                    ("deployments", {}),
                    *[("threat_intel", {"ip": ip}) for ip in inc.attacker_ips],
                    ("scan_ci_repo", {}),
                    *([("account_wide_hunt", {})] if self.run.store.supports_sql and inc.attacker_ips else [])]
        for name, args in required:
            key = {"baseline_profile": f"baseline:{args.get('identity')}", "deployments": "deployments",
                   "threat_intel": f"intel:{args.get('ip')}", "scan_ci_repo": "semgrep",
                   "account_wide_hunt": "hunt"}[name]
            if key not in self.cache:
                result = getattr(self, name)(**args)
                self._on_tool(name, args, result)

    # ---- hypothesis scoring (deterministic) -----------------------------------------------------

    def _score(self) -> dict[str, tuple[float, list[dict]]]:
        inc = self.run.incident
        atk = self.run.attacker_events()
        fired = {}
        for s in inc.signals:
            fired.setdefault(s.detector, []).extend(s.evidence_ids)
        deploys = self.facts.get("deployments", [])
        first, last = atk[0].time, atk[-1].time
        deploy_overlap = [d for d in deploys if first - timedelta(minutes=2) <= parse_time(d["time"]) <= last]
        deploy_near = [d for d in deploys if timedelta(0) <= first - parse_time(d["time"]) <= timedelta(minutes=10)]
        intel = list(self.facts.get("intel", {}).values())
        blocklisted = [i for i in intel if i.get("blocklists")]
        unknown = [i for i in intel if not i.get("blocklists") and i.get("category") != "ci-runner"]
        leaks = [f for f in self.facts.get("semgrep", []) if f["severity"] == "ERROR"]
        ci_like = [e for e in atk if e.name == "AssumeRole" and
                   str((e.raw.get("requestParameters") or {}).get("roleSessionName", "")).startswith("gha-")]
        intel_ids = [i["evidence_id"] for i in intel]

        def f(label, w, ids, cond=True):
            return {"label": label, "weight": w, "evidence_ids": ids} if cond else None

        labels = {
            "new_source_network": ("Never-seen source network", 0.6),
            "new_user_agent": ("Unfamiliar client / user agent", 0.4),
            "access_key_created": ("New long-lived access key minted", 0.6),
            "fresh_key_usage": ("Minted key used within minutes", 0.4),
            "rapid_iam_enumeration": ("Rapid IAM enumeration", 0.4),
            "sensitive_resource_access": ("Critical data accessed", 0.5),
            "access_denied_sensitive": ("Denied access to critical asset", 0.2),
            "first_time_resource_access": ("First-time access to a resource", 0.3),
        }
        comp = [f(*labels.get(d, (f"Learned detector: {d}", 0.4)), ids) for d, ids in fired.items()]
        comp += [
            f("No deployment covers the activity", 0.4, [self.facts.get("deployments_eid")] if
              self.facts.get("deployments_eid") else [], not deploy_overlap),
            f("Credential leak vector found in CI code", 0.6, [x["evidence_id"] for x in leaks], bool(leaks)),
            f("Source IP on threat blocklists", 0.6, intel_ids, bool(blocklisted)),
        ]
        admin = [
            f("Prior probability of legitimate operator activity", 1.0, []),
            f("Deployment by same identity minutes earlier", 0.5, [self.facts.get("deployments_eid")]
              if self.facts.get("deployments_eid") else [], bool(deploy_near)),
            f("Source IP has no negative reputation", 0.3, intel_ids, bool(unknown)),
        ]
        auto = [
            f("Prior probability of automation misconfiguration", 0.8, []),
            f("Session name follows CI convention (gha-*)", 0.3, [e.evidence_id for e in ci_like], bool(ci_like)),
        ]
        groups = {k: [x for x in v if x] for k, v in
                  {"credential_compromise": comp, "legitimate_admin": admin, "automation_error": auto}.items()}
        scores = {k: sum(x["weight"] for x in v) for k, v in groups.items()}
        z = sum(math.exp(s) for s in scores.values())
        self.facts.update(deploy_near=deploy_near, deploy_overlap=deploy_overlap, leaks=leaks, unknown_intel=unknown)
        return {k: (round(math.exp(scores[k]) / z, 3), groups[k]) for k in groups}

    # ---- offline narrative ----------------------------------------------------------------------

    def _offline_claims(self) -> dict[str, dict[str, Any]]:
        run, inc = self.run, self.run.incident
        atk = run.attacker_events()
        by = lambda pred: [e.evidence_id for e in atk if pred(e)]  # noqa: E731
        first = atk[0]
        intel = next(iter(self.facts.get("intel", {}).values()), {})
        base = self.facts.get("baselines", {}).get(inc.principal, {})
        role_base = next((v for k, v in self.facts.get("baselines", {}).items() if k != inc.principal), {})
        created = next((e for e in atk if e.name == "CreateAccessKey"), None)
        reads = [e for e in atk if e.iam_action == "s3:GetObject" and e.succeeded]
        read_buckets = Counter(resource_family(e.resource) for e in reads)
        enum = by(lambda e: e.source == "iam" and e.name.startswith(("List", "Get")))
        denied = by(lambda e: bool(e.error))
        deploy_eid = self.facts.get("deployments_eid")
        leak_ids = [x["evidence_id"] for x in self.facts.get("leaks", [])]

        fired = {s.detector for s in inc.signals}
        where = "never-seen network" if "new_source_network" in fired else "a network seen in its baseline"
        sup = [Claim(text=f"CI credential {first.origin_key or first.access_key} used from {where} "
                          f"{network(first.ip)} ({intel.get('org') or 'unknown org'}) with client "
                          f"'{ua_family(first.user_agent)}'",
                     evidence_ids=[first.evidence_id, intel.get("evidence_id"), base.get("evidence_id")])]
        for s in inc.signals:
            if s.detector not in {"new_source_network", "new_user_agent", "rapid_iam_enumeration",
                                  "access_key_created", "fresh_key_usage", "sensitive_resource_access",
                                  "access_denied_sensitive", "first_time_resource_access"}:
                sup.append(Claim(text=f"Learned detector {s.detector}: {s.title}", evidence_ids=s.evidence_ids))
        if enum:
            sup.append(Claim(text=f"{len(enum)} IAM discovery calls (users, roles, own policies) — {inc.principal} "
                                  f"made zero IAM read calls in 30 days", evidence_ids=enum[:6] + [base.get("evidence_id")]))
        if created:
            new_key = (created.raw.get("responseElements") or {}).get("accessKey", {}).get("accessKeyId")
            use = next((e for e in atk if e.access_key == new_key and e.name == "AssumeRole"), None)
            sup.append(Claim(text=f"Persistence: new access key {new_key} minted at {created.time:%H:%M:%S}"
                                  + (f" and used {int((use.time - created.time).total_seconds())}s later to assume "
                                     f"{short_resource(use.resource)}" if use else ""),
                             evidence_ids=[created.evidence_id] + ([use.evidence_id] if use else [])))
        for bucket, n in read_buckets.items():
            sup.append(Claim(text=f"{n} objects read from {short_resource(bucket)} — never accessed by the CI role "
                                  f"in its 30-day baseline", evidence_ids=[e.evidence_id for e in reads
                                                                           if resource_family(e.resource) == bucket][:4]
                             + [role_base.get("evidence_id")]))
        if denied:
            sup.append(Claim(text="Attempted read of a production secret outside the role's permissions (denied)",
                             evidence_ids=denied))
        if leak_ids:
            sup.append(Claim(text="Semgrep: deploy workflow prints AWS_SECRET_ACCESS_KEY to CI logs and dumps env "
                                  "into a build artifact — a concrete leak vector for this key",
                             evidence_ids=leak_ids))
        if not self.facts.get("deploy_overlap"):
            sup.append(Claim(text=f"No deployment or change ticket covers {atk[0].time:%H:%M}–{atk[-1].time:%H:%M}",
                             evidence_ids=[deploy_eid]))
        counter = []
        if self.facts.get("unknown_intel"):
            counter.append(Claim(text=f"Source IP {first.ip} has no threat-intel reputation (not on blocklists)",
                                 evidence_ids=[intel.get("evidence_id")]))
        if self.facts.get("deploy_near"):
            d = self.facts["deploy_near"][0]
            counter.append(Claim(text=f"{d['id']} ran at {d['time'][11:19]}, minutes before the activity, from "
                                      f"the same CI identity", evidence_ids=[deploy_eid]))
        clean = lambda cs: [Claim(text=c.text, evidence_ids=[i for i in c.evidence_ids if i]) for c in cs]  # noqa: E731
        return {
            "credential_compromise": {
                "title": "Compromised CI credential (leaked access key)",
                "supporting": clean(sup), "counter": clean(counter),
                "reasoning": "The activity combines a never-seen network and client with discovery, persistence "
                             "(new key), role assumption and bulk reads of data this identity has never touched. "
                             "No deployment explains it, and the CI code exposes the key in logs."},
            "legitimate_admin": {
                "title": "Legitimate operator debugging CI",
                "supporting": clean([Claim(text="All calls used valid credentials and an existing role; a deploy ran "
                                                "minutes earlier", evidence_ids=[deploy_eid])]),
                "counter": clean([Claim(text="No change ticket; operators use the admin account, not the CI key",
                                        evidence_ids=[deploy_eid]),
                                  Claim(text="Debugging does not require minting a new key or reading 14 customer "
                                             "contracts/KYC files", evidence_ids=[e.evidence_id for e in reads[:2]])]),
                "reasoning": "Possible only if an engineer used the CI key from a personal VPS, which would itself "
                             "be a policy violation."},
            "automation_error": {
                "title": "Misconfigured automation",
                "supporting": clean([Claim(text="Role session name 'gha-debug' follows CI naming",
                                           evidence_ids=by(lambda e: e.name == "AssumeRole"))]),
                "counter": clean([Claim(text="Network and client differ from every CI run in the baseline",
                                        evidence_ids=[first.evidence_id, base.get("evidence_id")])]),
                "reasoning": "Automation is repetitive and stays within its baseline; this activity is exploratory."},
        }

    def run_agent(self) -> None:
        run, inc = self.run, self.run.incident
        run.log(self.NAME, "start", f"Investigating {inc.principal}: gathering baseline, deployments, intel, code")
        llm_out: dict[str, Any] | None = None
        if run.llm.available:
            system = (
                "You are a senior AWS incident responder. Investigate the alert using tools; every claim must cite "
                "evidence_id values returned by tools or listed in the alert. Never invent IDs. Consider "
                "alternative explanations and record counter-evidence honestly.\n"
                "Final JSON format: {\"hypotheses\": [{\"id\": one of credential_compromise|legitimate_admin|"
                "automation_error, \"title\": str, \"supporting\": [{\"text\": str, \"evidence_ids\": [str]}], "
                "\"counter\": [{\"text\": str, \"evidence_ids\": [str]}], \"reasoning\": str}], "
                "\"summary\": str}")
            alert = {"principal": inc.principal, "signals": [s.model_dump(mode="json") for s in inc.signals],
                     "attacker_ips": inc.attacker_ips, "suspicious_activity": _brief_events(run.attacker_events())}
            try:
                llm_out = run.llm.tool_loop(system, json.dumps(alert, default=str), self._tools(), self._on_tool)
            except Exception as exc:  # noqa: BLE001
                run.log(self.NAME, "error", f"LLM investigation failed ({exc}); using deterministic reasoning")
        self._gather_required()
        memory_claim = self._recall()
        scores = self._score()
        offline = self._offline_claims()
        for extra in (memory_claim, self._hunt_claim()):
            if extra:
                offline["credential_compromise"]["supporting"].append(extra)
        hyps = []
        llm_by_id = {h.get("id"): h for h in (llm_out or {}).get("hypotheses", [])}
        if llm_by_id:
            raw = [c for h in llm_by_id.values() for c in (h.get("supporting") or []) + (h.get("counter") or [])]
            kept = sum(len(_claims(run, (h.get("supporting") or []) + (h.get("counter") or [])))
                       for h in llm_by_id.values())
            if kept < len(raw):
                run.log(self.NAME, "decision", f"Discarded {len(raw) - kept} LLM claim(s) citing nonexistent evidence")
        for hid, (conf, factors) in sorted(scores.items(), key=lambda kv: -kv[1][0]):
            h = llm_by_id.get(hid)
            sup = _claims(run, h.get("supporting")) if h else []
            cnt = _claims(run, h.get("counter")) if h else []
            base = offline[hid]
            hyps.append(Hypothesis(id=hid, title=(h or {}).get("title") or base["title"], confidence=conf,
                                   supporting=sup or base["supporting"], counter=cnt or base["counter"],
                                   reasoning=(h or {}).get("reasoning") or base["reasoning"],
                                   factors=[{**x, "evidence_ids": [i for i in x["evidence_ids"] if i]}
                                            for x in factors]))
        with run.lock:
            inc.hypotheses = hyps
        top = hyps[0]
        run.log(self.NAME, "result", f"Leading hypothesis: {top.title} ({top.confidence:.0%}); "
                                     f"{len(top.supporting)} supporting, {len(top.counter)} counter-evidence")


# ================================================================================================
# Attack reconstruction
# ================================================================================================

MITRE = {
    "iam:ListUsers": ("Discovery", "T1087.004 Account Discovery: Cloud Account"),
    "iam:ListRoles": ("Discovery", "T1069.003 Permission Groups Discovery: Cloud Groups"),
    "iam:ListAttachedUserPolicies": ("Discovery", "T1069.003 Permission Groups Discovery: Cloud Groups"),
    "iam:GetUserPolicy": ("Discovery", "T1069.003 Permission Groups Discovery: Cloud Groups"),
    "iam:GetRolePolicy": ("Discovery", "T1069.003 Permission Groups Discovery: Cloud Groups"),
    "iam:CreateAccessKey": ("Persistence", "T1098.001 Account Manipulation: Additional Cloud Credentials"),
    "sts:AssumeRole": ("Privilege Escalation", "T1078.004 Valid Accounts: Cloud Accounts (role assumption)"),
    "sts:GetCallerIdentity": ("Discovery", "T1087.004 Account Discovery: Cloud Account"),
    "s3:ListAllMyBuckets": ("Discovery", "T1619 Cloud Storage Object Discovery"),
    "s3:ListBucket": ("Discovery", "T1619 Cloud Storage Object Discovery"),
    "s3:GetObject": ("Collection", "T1530 Data from Cloud Storage"),
    "secretsmanager:GetSecretValue": ("Credential Access", "T1555.006 Credentials from Password Stores: Cloud "
                                                           "Secrets Management Stores"),
}


def reconstruct(run: Run) -> None:
    name = "Reconstruction"
    run.log(name, "start", "Mapping attributed CloudTrail activity to MITRE ATT&CK")
    atk = run.attacker_events()
    entries: list[TimelineEntry] = []
    for i, e in enumerate(atk):
        tactic, tech = ("Initial Access", "T1078.004 Valid Accounts: Cloud Accounts") if i == 0 else \
            MITRE.get(e.iam_action, ("Execution", e.iam_action))
        label = e.name + (f" {short_resource(resource_family(e.resource))}" if e.resource != "*" else "") + \
            (" (denied)" if e.error else "")
        if entries and entries[-1].tactic == tactic and entries[-1].technique == tech:
            last = entries[-1]
            last.end = e.time
            last.evidence_ids.append(e.evidence_id)
            if label not in last.actions:
                last.actions.append(label)
        else:
            entries.append(TimelineEntry(start=e.time, end=e.time, tactic=tactic, technique=tech, actions=[label],
                                         evidence_ids=[e.evidence_id]))
    for t in entries:
        counts = Counter(run.state.evidence[i].raw["eventName"] for i in t.evidence_ids)
        t.actions = [a + (f" ×{counts[a.split(' ')[0]]}" if counts[a.split(' ')[0]] > 1 and a.split(' ')[0] in
                          counts else "") for a in t.actions]
    with run.lock:
        run.incident.timeline = entries
    tactics = list(OrderedDict.fromkeys(t.tactic for t in entries))
    narrative = (f"An existing CI credential was used from {atk[0].ip} for IAM discovery, followed by creation of a "
                 f"persistent access key, assumption of the deploy role, and reads of storage and secrets the identity "
                 f"had never accessed. Kill chain: {' → '.join(tactics)}.")
    if run.llm.available:
        try:
            out = run.llm.json(
                "You are a threat analyst. Write a 2-3 sentence attack narrative from this ATT&CK timeline for an "
                "incident report. Be factual; no speculation beyond the data. JSON: {\"narrative\": str}",
                json.dumps([t.model_dump(mode="json") for t in entries]))
            narrative = out.get("narrative") or narrative
        except Exception as exc:  # noqa: BLE001
            run.log(name, "error", f"LLM narrative failed ({exc}); using template")
    with run.lock:
        run.incident.narrative = narrative
    run.log(name, "result", f"{len(entries)} stages reconstructed: {' → '.join(tactics)}")


# ================================================================================================
# Blast radius
# ================================================================================================

def blast_radius(run: Run) -> None:
    name = "Blast Radius"
    inc = run.incident
    run.log(name, "start", f"Building access graph for {inc.principal} and enumerating paths to critical assets")
    now = run.now()
    compromised = set(inc.attacker_keys)
    graph = build_graph(run.prod, inc.principal, compromised, now)
    paths = attack_paths(run.prod, inc.principal, compromised, now)
    reachable = sorted({p.target_name for p in paths})
    accessed = sorted({short_resource(resource_family(e.resource)) for e in run.attacker_events()
                       if e.succeeded and resource_family(e.resource) in run.engine.critical})
    via_comp = [p for p in paths if p.compromised_credential]
    summary = (f"{len(via_comp)} attack paths from compromised credentials reach {len(reachable)} critical assets "
               f"({', '.join(reachable)}). Already accessed during the incident: {', '.join(accessed) or 'none'}. "
               f"Root cause of the exposure: ci-deploy-role grants S3 on arn:aws:s3:::* and ci-deployer can mint its "
               f"own access keys.")
    br = BlastRadius(graph_before=graph, paths_before=paths, critical_assets_reachable=reachable,
                     accessed_during_incident=accessed, summary=summary)
    with run.lock:
        inc.blast_radius = br
    run.log(name, "result", f"{len(paths)} paths ({len(via_comp)} via compromised credentials) to "
                            f"{len(reachable)} critical assets", {"paths": len(paths)})


# ================================================================================================
# Remediation planner
# ================================================================================================

class Planner:
    NAME = "Remediation Planner"

    def __init__(self, run: Run) -> None:
        self.run = run
        self.n = 0

    def conditions(self, params: dict[str, Any]) -> set[str]:
        run = self.run
        c = set()
        if params.get("key_id") and params["key_id"] == run.prod.ci_credential["key_id"]:
            c.add("key_in_use_by_ci")
        minted = {k for k, ev in run.engine.minted_keys.items() if run.engine.is_attacker_event(
            run.incident.principal, ev)}
        if params.get("key_id") in minted:
            c.add("key_minted_during_incident")
        return c

    def _playbook(self, kind: str, params: dict[str, Any], rationale: str) -> tuple[str | None, str]:
        for pb in self.run.knowledge.playbooks:
            w = pb.get("when", {})
            if w.get("kind") == kind and set(w.get("conditions", [])) <= self.conditions(params):
                new_kind = pb["then"]["kind"]
                self.run.log(self.NAME, "decision", f"Applied learned playbook {pb['id']} (from "
                                                    f"{pb.get('learned_from', '?')}): {kind} → {new_kind}")
                return (None if new_kind == "skip" else new_kind), \
                    f"Playbook {pb['id']}: {pb.get('reason', '')} (learned from {pb.get('learned_from', '?')})"
        return kind, rationale

    def _make(self, kind: str, params: dict[str, Any], rationale: str, evidence_ids: list[str],
              attempt: int, use_playbooks: bool = True) -> Action | None:
        run = self.run
        if use_playbooks:
            kind, rationale = self._playbook(kind, params, rationale)
            if kind is None:
                return None
        try:
            validate(kind, params, run.prod)
        except ValueError as exc:
            run.log(self.NAME, "error", f"Rejected proposed action {kind}: {exc}")
            return None
        self.n += 1
        return Action(id=f"A{self.n}", kind=kind, title=title_for(kind, params), target=target_for(kind, params),
                      risk=risk_for(kind, params, run.prod, set(run.incident.attacker_keys)), rationale=rationale,
                      evidence_ids=run.valid_ids(evidence_ids), params=params, attempt=attempt)

    def _context(self) -> dict[str, Any]:
        run, inc = self.run, self.run.incident
        atk = run.attacker_events()
        ci = run.prod.ci_credential
        creds = []
        for k in inc.attacker_keys:
            if k.startswith("ASIA"):
                creds.append({"id": k, "type": "sts_session", "role": run.prod.d["sessions"].get(k, {}).get("role")})
            else:
                owner = run.prod.key(k)
                creds.append({"id": k, "type": "access_key", "user": owner[0] if owner else None,
                              "used_by_production_ci": k == ci["key_id"],
                              "minted_during_incident": any(
                                  (e.raw.get("responseElements") or {}).get("accessKey", {}).get("accessKeyId") == k
                                  for e in atk)})
        secrets = sorted({e.resource for e in atk if e.iam_action == "secretsmanager:GetSecretValue" and e.succeeded})
        return {"principal": inc.principal, "compromised_credentials": creds, "secrets_read_by_attacker": secrets,
                "roles_used": sorted({e.principal for e in atk if e.principal_type == "AssumedRole"}),
                "user_policies": list(run.prod.policies("user", inc.principal)),
                "role_policies": {r: list(run.prod.policies("role", r)) for r in
                                  {e.principal for e in atk if e.principal_type == "AssumedRole"}},
                "blast_radius": inc.blast_radius.summary if inc.blast_radius else "",
                "evidence_index": {e.evidence_id: Run.describe(e) for e in atk}}

    def _offline(self, attempt: int) -> list[Action]:
        ctx = self._context()
        atk = self.run.attacker_events()
        ev = lambda pred: [e.evidence_id for e in atk if pred(e)]  # noqa: E731
        acts: list[Action | None] = [self._make("snapshot_evidence", {}, "Preserve forensic state before any change",
                                                [atk[0].evidence_id, atk[-1].evidence_id], attempt)]
        for c in ctx["compromised_credentials"]:
            if c["type"] == "access_key" and c.get("minted_during_incident"):
                acts.append(self._make("deactivate_access_key", {"user": c["user"], "key_id": c["id"]},
                                       "Key was minted by the attacker for persistence",
                                       ev(lambda e: e.name == "CreateAccessKey"), attempt))
        for role in ctx["roles_used"]:
            acts.append(self._make("revoke_role_sessions", {"role": role},
                                   "Stolen STS session remains valid after key deactivation",
                                   ev(lambda e: e.name == "AssumeRole"), attempt))
        for c in ctx["compromised_credentials"]:
            if c["type"] == "access_key" and not c.get("minted_during_incident"):
                acts.append(self._make("deactivate_access_key", {"user": c["user"], "key_id": c["id"]},
                                       "Containment-first: the leaked key was used by the attacker",
                                       ev(lambda e: e.access_key == c["id"])[:3], attempt))
        for p in ctx["user_policies"]:
            acts.append(self._make("restrict_user_policy", {"user": ctx["principal"], "policy_name": p},
                                   "Policy allowed IAM enumeration and self-service key creation, which the CI job "
                                   "never uses", ev(lambda e: e.source == "iam")[:4], attempt))
        for role, pols in ctx["role_policies"].items():
            for p in pols:
                acts.append(self._make("restrict_role_policy", {"role": role, "policy_name": p},
                                       "S3 access on arn:aws:s3:::* exposed customer-documents and model-artifacts",
                                       ev(lambda e: e.iam_action == "s3:GetObject")[:3], attempt))
        for arn in ctx["secrets_read_by_attacker"]:
            acts.append(self._make("rotate_secret", {"secret_arn": arn}, "Attacker read the current secret value",
                                   ev(lambda e: e.resource == arn and e.succeeded), attempt))
        acts.append(self._make("delete_iam_user", {"user": ctx["principal"]},
                               "Considered: eliminates the identity entirely", [], attempt))
        return [a for a in acts if a]

    def _llm(self, attempt: int, failures: list[dict] | None, current: list[Action]) -> list[Action] | None:
        catalog = {k: {"params": v["params"], "description": v["description"]} for k, v in CATALOG.items()}
        system = ("You are the remediation planner for an AWS incident. Choose the minimum set of catalog actions "
                  "that fully contains the attacker while keeping production CI and the production API working. "
                  "Start with snapshot_evidence. Cite evidence_ids from evidence_index only. Risk tiers are assigned "
                  "by policy, not by you. JSON: {\"actions\": [{\"kind\": str, \"params\": {...}, \"rationale\": "
                  "str, \"evidence_ids\": [str]}]}")
        payload = {"catalog": catalog, "incident": self._context(),
                   "lessons_from_past_incidents": self.run.knowledge.playbooks}
        if failures:
            payload["previous_plan"] = [{"kind": a.kind, "params": {k: v for k, v in a.params.items()
                                                                    if k != "new_policy"}} for a in current]
            payload["sandbox_failures"] = failures
        try:
            out = self.run.llm.json(system, json.dumps(payload, default=str))
        except Exception as exc:  # noqa: BLE001
            self.run.log(self.NAME, "error", f"LLM planning failed ({exc}); using deterministic planner")
            return None
        acts = [self._make(a.get("kind", ""), a.get("params") or {}, a.get("rationale", ""),
                           a.get("evidence_ids") or [], attempt) for a in out.get("actions", [])]
        acts = [a for a in acts if a]
        if not acts or acts[0].kind != "snapshot_evidence":
            snap = self._make("snapshot_evidence", {}, "Preserve forensic state before any change", [], attempt)
            acts = [snap] + [a for a in acts if a.kind != "snapshot_evidence"]
        return acts

    def plan(self) -> list[Action]:
        self.run.log(self.NAME, "start", "Drafting minimum containment plan from evidence and blast radius")
        acts = (self._llm(1, None, []) if self.run.llm.available else None) or self._offline(1)
        self._publish(acts, 1)
        return acts

    def revise(self, current: list[Action], failures: list[dict], culprits: list[Action], attempt: int) -> list[Action]:
        run = self.run
        run.log(self.NAME, "start", f"Revising plan: {len(failures)} sandbox check(s) failed; culprit(s): "
                                    f"{', '.join(a.id for a in culprits) or 'unknown'}")
        new = self._llm(attempt, failures, current) if run.llm.available else None
        if new is None:
            new = []
            for a in current:
                if a in culprits and a.kind == "deactivate_access_key" and \
                        a.params["key_id"] == run.prod.ci_credential["key_id"]:
                    rep = self._make("rotate_access_key", dict(a.params),
                                     f"{a.id} broke production CI (key still in use). Rotate instead: issue a new key, "
                                     f"update the GitHub secret, then deactivate the leaked key", a.evidence_ids,
                                     attempt, use_playbooks=False)
                    new.append(rep)
                    run.log(self.NAME, "decision", f"Replace {a.id} (deactivate) with {rep.id} (rotate + update CI "
                                                   f"secret)")
                elif a in culprits:
                    run.log(self.NAME, "decision", f"Drop {a.id}: breaks legitimate workload")
                else:
                    new.append(a.model_copy(update={"attempt": attempt, "status": "proposed"}))
        for c in culprits:
            rep = next((n for n in new if n.target == c.target and n.kind != c.kind), None)
            run.repairs.append({
                "culprit_kind": c.kind, "conditions": sorted(self.conditions(c.params)),
                "replacement_kind": rep.kind if rep else "skip",
                "failed_checks": [f["name"] for f in failures], "incident": run.incident.id,
                "scenario": run.scenario_id})
        for a in current:
            if not any(n.id == a.id for n in new):
                a.status, a.status_reason = "superseded", f"replaced in plan v{attempt}"
        self._publish(new, attempt)
        return new

    def _publish(self, acts: list[Action], attempt: int) -> None:
        run = self.run
        for a in acts:
            if a.risk == "dangerous":
                a.status, a.status_reason = "blocked", "Dangerous/irreversible — blocked by Sentinel policy"
        with run.lock:
            run.incident.actions = [a for a in run.incident.actions if a.status == "superseded"] + acts
        tiers = Counter(a.risk for a in acts)
        run.log(self.NAME, "result", f"Plan v{attempt}: {len(acts)} actions — {tiers.get('safe', 0)} safe, "
                                     f"{tiers.get('review', 0)} need review, {tiers.get('dangerous', 0)} blocked")


# ================================================================================================
# Verifier
# ================================================================================================

class Verifier:
    NAME = "Verifier"

    def __init__(self, run: Run) -> None:
        self.run = run
        self.executor = Executor(run.store.observed_permissions, run.state.evidence, None)

    def _suite(self, state, actions, env, attempt):
        inc = self.run.incident
        return run_suite(state, user=inc.principal, attacker_events=self.run.attacker_events(),
                         compromised=set(inc.attacker_keys),
                         secret_versions_at_incident=self.run.secret_versions_at_incident, actions=actions,
                         observed=self.run.store.observed_permissions, now=self.run.now(), environment=env,
                         attempt=attempt, paths_before=len(inc.blast_radius.paths_before))

    def _apply_all(self, actions: list[Action]):
        sb = self.run.prod.clone()
        applied = []
        for a in actions:
            if a.risk == "dangerous" or a.status in ("blocked", "superseded"):
                continue
            a.rollback = self.executor.apply(sb, a, self.run.now())
            applied.append(a)
        return sb, applied

    def sandbox(self, actions: list[Action], attempt: int) -> tuple[bool, list[dict], list[Action]]:
        run = self.run
        run.log(self.NAME, "start", f"Sandbox attempt {attempt}: cloning production IAM, applying "
                                    f"{sum(a.risk != 'dangerous' for a in actions)} actions, replaying the attack")
        sb, applied = self._apply_all(actions)
        checks = self._suite(sb, applied, "sandbox", attempt)
        with run.lock:
            run.incident.verification = [c for c in run.incident.verification if c.attempt != attempt
                                         or c.environment != "sandbox"] + checks
        failed = [c for c in checks if not c.passed]
        culprits: list[Action] = []
        if failed:
            failing = {c.name for c in failed}
            for a in applied:
                if a.kind == "snapshot_evidence":
                    continue
                sb2, without = self._apply_all([x for x in applied if x is not a])
                still = {c.name for c in self._suite(sb2, without, "sandbox", attempt) if not c.passed}
                if any(f not in still for f in failing if not f.startswith(("No compromised", "Stolen"))):
                    culprits.append(a)
            for a in applied:
                a.status = "sandbox_fail"
            run.log(self.NAME, "result", f"FAIL — {len(failed)}/{len(checks)} checks failed: "
                                         f"{'; '.join(c.name for c in failed[:3])}. Ablation isolates "
                                         f"{', '.join(a.id for a in culprits) or 'no single action'}",
                    {"failed": [c.name for c in failed]})
        else:
            for a in applied:
                a.status = "sandbox_pass"
            run.log(self.NAME, "result", f"PASS — {len(checks)}/{len(checks)} checks: attack blocked, CI and "
                                         f"production API healthy")
        run.changed()
        return not failed, [c.model_dump(include={"name", "detail"}) for c in failed], culprits

    def production(self, actions: list[Action], attempt: int) -> bool:
        run = self.run
        applied = [a for a in actions if a.status == "executed"]
        checks = self._suite(run.prod, applied, "production", attempt)
        with run.lock:
            run.incident.verification += checks
        ok = all(c.passed for c in checks)
        run.log(self.NAME, "result", f"Production verification {'PASS' if ok else 'FAIL'} — "
                                     f"{sum(c.passed for c in checks)}/{len(checks)} checks")
        return ok


def execute(run: Run, actions: list[Action], verifier: Verifier) -> None:
    ex = Executor(run.store.observed_permissions, run.state.evidence, run.run_dir)
    for a in actions:
        if a.status != "approved":
            continue
        a.rollback = ex.apply(run.prod, a, run.now())
        a.status, a.executed_at = "executed", run.now()
        run.log("Executor", "result", f"{a.id} executed in production: {a.title}",
                {"rollback": {k: v for k, v in (a.rollback or {}).items() if k != "previous_policy"}})


# ================================================================================================
# Post-incident blast radius + postmortem
# ================================================================================================

def finalize_blast_radius(run: Run) -> None:
    inc = run.incident
    now = run.now()
    compromised = set(inc.attacker_keys)
    after = build_graph(run.prod, inc.principal, compromised, now)
    paths = attack_paths(run.prod, inc.principal, compromised, now)
    with run.lock:
        inc.blast_radius.graph_after = diff_graph(inc.blast_radius.graph_before, after)
        inc.blast_radius.paths_after = paths
    before = len(inc.blast_radius.paths_before)
    red = 1 - len(paths) / before if before else 0
    run.log("Blast Radius", "result", f"Attack paths {before} → {len(paths)} ({red:.0%} reduction); "
                                      f"{sum(p.compromised_credential for p in paths)} via compromised credentials")


def postmortem(run: Run) -> None:
    name = "Postmortem"
    inc = run.incident
    run.log(name, "start", "Writing incident report")
    atk = run.attacker_events()
    br = inc.blast_radius
    executed = [a for a in inc.actions if a.status == "executed"]
    prod_checks = [c for c in inc.verification if c.environment == "production"]
    reads = [e for e in atk if e.iam_action == "s3:GetObject" and e.succeeded]
    top = inc.hypotheses[0] if inc.hypotheses else None
    contain_s = int(run.wall_contained - run.wall_opened) if run.wall_contained and run.wall_opened else None
    leak = [f for f in inc_semgrep(run)]
    lines = [
        f"# Incident {inc.id} — {inc.title}",
        "",
        f"**Severity:** {inc.severity} · **Status:** {inc.status} · **Principal:** `{inc.principal}`",
        f"**Attack window:** {atk[0].time:%Y-%m-%d %H:%M:%S} – {atk[-1].time:%H:%M:%S} UTC "
        f"({int((atk[-1].time - atk[0].time).total_seconds() // 60)}m {int((atk[-1].time - atk[0].time).total_seconds() % 60)}s)",
        f"**Sentinel time to verified containment:** {contain_s}s" if contain_s is not None else "",
        "",
        "## Root cause",
        f"{top.title} — {top.confidence:.0%} (alternatives: "
        + ", ".join(f"{h.title} {h.confidence:.0%}" for h in inc.hypotheses[1:]) + ")" if top else "",
        "",
        inc.narrative,
        "",
        "## Impact",
        f"- {len(reads)} objects read from {', '.join(sorted({short_resource(resource_family(e.resource)) for e in reads}))}"
        + f" [{', '.join(e.evidence_id for e in reads[:3])}…]" if reads else "- No object reads",
        *[f"- Secret read: `{short_resource(e.resource)}` [{e.evidence_id}]" for e in atk
          if e.iam_action == "secretsmanager:GetSecretValue" and e.succeeded],
        *[f"- Attempted (denied): `{e.iam_action}` on `{short_resource(e.resource)}` [{e.evidence_id}]" for e in atk
          if e.error],
        f"- Critical assets reachable before containment: {', '.join(br.critical_assets_reachable)}",
        "",
        "## Timeline (MITRE ATT&CK)",
        *[f"- **{t.start:%H:%M:%S}** {t.tactic} — {t.technique}: {', '.join(t.actions)} "
          f"[{', '.join(t.evidence_ids[:3])}{'…' if len(t.evidence_ids) > 3 else ''}]" for t in inc.timeline],
        "",
        "## Containment & remediation",
        *[f"- `{a.id}` [{a.risk.upper()}] {a.title} — {a.rationale}" for a in executed],
        *[f"- `{a.id}` blocked: {a.title} ({a.status_reason})" for a in inc.actions if a.status == "blocked"],
        *[f"- `{a.id}` superseded: {a.title} ({a.status_reason})" for a in inc.actions if a.status == "superseded"],
        "",
        "## Verification",
        f"- Attack paths: {len(br.paths_before)} → {len(br.paths_after or [])}",
        f"- Production checks: {sum(c.passed for c in prod_checks)}/{len(prod_checks)} passing",
        *[f"- {'✅' if c.passed else '❌'} {c.name} — {c.detail}" for c in prod_checks],
        "",
        "## Why detection worked",
        *[f"- `{s.detector}`: {s.title}" for s in inc.signals],
        "",
        "## Why existing controls failed",
        *[f"- {f['message']} (`{f['path']}:{f['line']}`)" for f in leak],
        "- CI used a long-lived IAM user key instead of GitHub OIDC federation",
        "- `ci-deploy-role` granted S3 on `arn:aws:s3:::*`; `ci-deployer` could mint its own access keys",
        "",
        "## Preventive actions",
        "1. Replace the CI access key with GitHub Actions OIDC (short-lived, repo-scoped role assumption)",
        "2. Keep the least-privilege policies generated from observed usage; add a CI check that rejects wildcards",
        "3. Remove credential echo / `set -x` / env dumps from the workflow; enforce the Semgrep rules in CI",
        "4. Alert on CreateAccessKey by non-human identities and on first-time access to critical buckets",
    ]
    report = "\n".join(lines)
    if run.llm.available:
        try:
            out = run.llm.json(
                "You are an SRE writing a blameless postmortem. Improve the clarity of this markdown report without "
                "changing any facts, numbers, or [E#] evidence references. Keep all sections. "
                "JSON: {\"markdown\": str}", report)
            report = out.get("markdown") or report
        except Exception as exc:  # noqa: BLE001
            run.log(name, "error", f"LLM postmortem failed ({exc}); using template")
    with run.lock:
        inc.postmortem = report
    if run.run_dir:
        run.run_dir.mkdir(parents=True, exist_ok=True)
        (run.run_dir / "postmortem.md").write_text(report)
    run.log(name, "result", f"Report written ({len(report.splitlines())} lines)")


def remember_incident(run: Run) -> None:
    inc = run.incident
    kb.remember({
        "incident_id": inc.id, "run_id": run.state.run_id, "date": inc.opened_at.isoformat(),
        "scenario": run.scenario_id, "knowledge_version": run.knowledge.version, "principal": inc.principal,
        "detectors": sorted({s.detector for s in inc.signals}),
        "root_cause": inc.hypotheses[0].title if inc.hypotheses else "",
        "plan_attempts": max((a.attempt for a in inc.actions), default=1),
        "repairs": run.repairs,
        "final_actions": [a.kind for a in inc.actions if a.status == "executed"],
        "paths_before": len(inc.blast_radius.paths_before) if inc.blast_radius else None,
        "paths_after": len(inc.blast_radius.paths_after or []) if inc.blast_radius else None,
        "status": inc.status,
    })
    run.log("Postmortem", "result", "Incident stored in episodic memory for future investigations")


def inc_semgrep(run: Run) -> list[dict]:
    return [e.raw for e in run.state.evidence.values() if e.source == "semgrep" and e.raw.get("severity") == "ERROR"]
