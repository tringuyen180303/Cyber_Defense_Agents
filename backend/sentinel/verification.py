"""Verification suite: replay the attack, exercise legitimate workloads, measure exposure, check guardrails."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Callable, Literal

from .cloudtrail import short_resource
from .graph import attack_paths
from .iam import IamState
from .models import Action, CheckResult, Event

WILDCARD_ONLY_ACTIONS = {"ecr:GetAuthorizationToken", "s3:ListAllMyBuckets"}


def _concrete(resource: str) -> str:
    return resource[:-1] + "healthcheck" if resource.endswith("/*") else resource


def run_suite(
    state: IamState,
    *,
    user: str,
    attacker_events: list[Event],
    compromised: set[str],
    secret_versions_at_incident: dict[str, int],
    actions: list[Action],
    observed: Callable[[str], Counter],
    now: datetime,
    environment: Literal["sandbox", "production"],
    attempt: int,
    paths_before: int,
) -> list[CheckResult]:
    checks: list[CheckResult] = []
    n = 0

    def add(category, name, passed, detail, items=None):
        nonlocal n
        n += 1
        checks.append(CheckResult(id=f"{environment[0]}{attempt}-{n}", category=category, name=name,
                                  passed=passed, detail=detail, environment=environment, attempt=attempt,
                                  items=items or []))

    # ---- 1. attack replay -----------------------------------------------------------------------
    role_arns = {r["arn"] for r in state.roles.values()}
    user_arn = state.users[user]["arn"]
    probes: dict[str, list[tuple[str, str, str]]] = {}
    for e in attacker_events:
        if e.succeeded:
            probes.setdefault(e.access_key, []).append((e.iam_action, e.resource, e.ip))
    attacker_ip = attacker_events[0].ip if attacker_events else None
    for key in sorted(compromised):
        if key.startswith("AKIA"):
            probes.setdefault(key, [])
            probes[key] += [("sts:AssumeRole", ra, attacker_ip) for ra in sorted(role_arns)
                            if user_arn in next(r for r in state.roles.values() if r["arn"] == ra)
                            .get("trust", {}).get("AWS", [])]
            probes[key].append(("iam:CreateAccessKey", user_arn, attacker_ip))

    labels = {}
    for key, ops in probes.items():
        kind = "Stolen STS session" if key.startswith("ASIA") else (
            "Leaked CI key" if key == _original_ci_key(state, compromised) else "Attacker-minted key")
        labels[key] = f"{kind} {key[:4]}…{key[-4:]}"
        seen: dict[tuple[str, str], dict] = {}
        for action, resource, ip in ops:
            d = state.evaluate(key, action, resource, now, ip)
            fam = short_resource(resource.split("/")[0] if resource.startswith("arn:aws:s3:::") else resource)
            item = seen.setdefault((action, fam), {"op": f"{action} {fam}", "count": 0, "denied": 0,
                                                    "reason": d.reason})
            item["count"] += 1
            item["denied"] += 0 if d.allowed else 1
            if d.allowed:
                item["reason"] = d.reason
        items = list(seen.values())
        blocked = sum(i["denied"] for i in items)
        total = sum(i["count"] for i in items)
        add("attack_blocked", f"{labels[key]}: attacker operations denied", blocked == total,
            f"{blocked}/{total} replayed operations denied", items)

    for arn, v0 in secret_versions_at_incident.items():
        res = state.resource(arn)
        add("attack_blocked", f"Stolen value of {res['name']} invalidated", res.get("version", 0) > v0,
            f"version at theft v{v0}, current v{res.get('version')}")

    # ---- 2. legitimate workloads ----------------------------------------------------------------
    t = now + timedelta(seconds=1)
    ci_key = state.ci_credential["key_id"]
    sim = state.clone()
    ci_role = "ci-deploy-role"
    ar = sim.assume_role(ci_key, ci_role, t, "ASIAQ3VERIFYCISESS01")
    add("app_healthy", f"CI pipeline can assume {ci_role} (key {ci_key[:4]}…{ci_key[-4:]})", ar.allowed, ar.reason)
    for (action, resource), _ in sorted(observed(ci_role).items()):
        d = sim.evaluate("ASIAQ3VERIFYCISESS01", action, _concrete(resource), t) if ar.allowed else None
        add("app_healthy", f"CI pipeline: {action} {short_resource(resource)}", bool(d and d.allowed),
            d.reason if d else "no session (AssumeRole failed)")

    sim.register_session("ASIAQ3VERIFYAPISESS1", "prod-api-role", t, None, None)
    for (action, resource), _ in sorted(observed("prod-api-role").items()):
        d = sim.evaluate("ASIAQ3VERIFYAPISESS1", action, _concrete(resource), t)
        add("app_healthy", f"Production API: {action} {short_resource(resource)}", d.allowed, d.reason)

    for admin in state.d.get("admins", []):
        k = next(k["id"] for k in state.users[admin]["access_keys"] if k["status"] == "Active")
        d = state.evaluate(k, "iam:ListUsers", "*", t)
        add("app_healthy", f"Security admin {admin} retains access", d.allowed, d.reason)

    # ---- 3. exposure ----------------------------------------------------------------------------
    after = attack_paths(state, user, compromised, now)
    compromised_after = [p for p in after if p.compromised_credential]
    add("exposure", "No compromised credential can reach a critical asset", not compromised_after,
        f"attack paths {paths_before} → {len(after)} "
        f"({len(compromised_after)} via compromised credentials)",
        [{"op": " → ".join(p.nodes[:1] + [p.target_name]), "count": 1, "denied": 0 if p.compromised_credential
          else 1, "reason": "residual (non-compromised credential)" if not p.compromised_credential
          else "still reachable"} for p in after])

    # ---- 4. guardrails --------------------------------------------------------------------------
    applied = actions
    add("guardrail", "No dangerous action executed", not any(a.risk == "dangerous" for a in applied),
        "dangerous actions are blocked by policy")
    bad = []
    for a in applied:
        for st in (a.params.get("new_policy") or {}).get("Statement", []):
            acts = st["Action"] if isinstance(st["Action"], list) else [st["Action"]]
            ress = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
            if any("*" in x for x in acts):
                bad.append(f"{a.id}: wildcard action {acts}")
            if any(r == "*" or r.startswith("arn:aws:s3:::*") for r in ress) and not set(acts) <= WILDCARD_ONLY_ACTIONS:
                bad.append(f"{a.id}: wildcard resource for {acts}")
    add("guardrail", "Generated policies are least-privilege (no wildcards)", not bad,
        "; ".join(bad) or "all generated statements scoped to observed resources")
    add("guardrail", "Every change is reversible", all(a.rollback is not None for a in applied if a.kind !=
                                                       "snapshot_evidence"),
        "rollback recorded for each applied change")
    return checks


def _original_ci_key(state: IamState, compromised: set[str]) -> str | None:
    keys = sorted((k for k in state.users[state.ci_credential["user"]]["access_keys"] if k["id"] in compromised),
                  key=lambda k: k["created"])
    return keys[0]["id"] if keys else None
