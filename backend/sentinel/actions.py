"""Remediation action catalog. Risk tiers are assigned here, never by the LLM."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .cloudtrail import short_resource
from .iam import IamState
from .models import Action, Evidence, Risk

CATALOG: dict[str, dict[str, Any]] = {
    "snapshot_evidence": {
        "risk": "safe", "params": {},
        "description": "Write a SHA-256-sealed copy of all incident evidence (CloudTrail records, IAM state).",
    },
    "deactivate_access_key": {
        "risk": "safe*", "params": {"user": "IAM user", "key_id": "access key id"},
        "description": "Set an access key to Inactive (reversible). SAFE for keys minted during the incident; "
                       "REVIEW for keys in use by production systems.",
    },
    "revoke_role_sessions": {
        "risk": "safe", "params": {"role": "IAM role"},
        "description": "Attach AWSRevokeOlderSessions deny policy (aws:TokenIssueTime < now). Kills stolen STS "
                       "sessions, which survive key deactivation. Legitimate callers simply re-assume the role.",
    },
    "rotate_access_key": {
        "risk": "review", "params": {"user": "IAM user", "key_id": "key to retire"},
        "description": "Create a replacement key, update the CI secret store, then deactivate the old key.",
    },
    "restrict_role_policy": {
        "risk": "review", "params": {"role": "IAM role", "policy_name": "inline policy to replace"},
        "description": "Replace the policy with least privilege generated from 30 days of observed usage.",
    },
    "restrict_user_policy": {
        "risk": "review", "params": {"user": "IAM user", "policy_name": "inline policy to replace"},
        "description": "Replace the user's policy with least privilege generated from observed usage.",
    },
    "rotate_secret": {
        "risk": "review", "params": {"secret_arn": "secret ARN"},
        "description": "Rotate a secret the attacker read; the stolen value stops working.",
    },
    "delete_iam_user": {
        "risk": "dangerous", "params": {"user": "IAM user"},
        "description": "Irreversible; destroys forensic state and breaks dependents. Never auto-executed.",
    },
}

ALWAYS_ALLOWED = {"sts:GetCallerIdentity"}


def least_privilege_policy(observed: Counter) -> dict[str, Any]:
    by_action: dict[str, set[str]] = {}
    for (action, resource), _ in observed.items():
        if action in ALWAYS_ALLOWED:
            continue
        by_action.setdefault(action, set()).add(resource)
    statements = [{"Sid": "Observed" + a.split(":")[1], "Effect": "Allow", "Action": a,
                   "Resource": sorted(rs) if len(rs) > 1 else next(iter(rs))}
                  for a, rs in sorted(by_action.items())]
    return {"Version": "2012-10-17", "Statement": statements}


def risk_for(kind: str, params: dict[str, Any], state: IamState, attacker_keys: set[str]) -> Risk:
    base = CATALOG[kind]["risk"]
    if base != "safe*":
        return base
    in_use = params.get("key_id") == state.ci_credential["key_id"]
    return "safe" if params.get("key_id") in attacker_keys and not in_use else "review"


def title_for(kind: str, p: dict[str, Any]) -> str:
    match kind:
        case "snapshot_evidence":
            return "Preserve evidence bundle (SHA-256 sealed)"
        case "deactivate_access_key":
            return f"Deactivate access key {p['key_id']}"
        case "revoke_role_sessions":
            return f"Revoke all active sessions for role {p['role']}"
        case "rotate_access_key":
            return f"Rotate CI key {p['key_id']} and update GitHub secret"
        case "restrict_role_policy":
            return f"Replace {p['role']}/{p['policy_name']} with least-privilege policy"
        case "restrict_user_policy":
            return f"Replace {p['user']}/{p['policy_name']} with least-privilege policy"
        case "rotate_secret":
            return f"Rotate {short_resource(p['secret_arn'])}"
        case "delete_iam_user":
            return f"Delete IAM user {p['user']}"
    return kind


def validate(kind: str, p: dict[str, Any], state: IamState) -> None:
    if kind not in CATALOG:
        raise ValueError(f"unknown action kind {kind}")
    if "user" in CATALOG[kind]["params"] and p.get("user") not in state.users:
        raise ValueError(f"unknown user {p.get('user')}")
    if "role" in CATALOG[kind]["params"] and p.get("role") not in state.roles:
        raise ValueError(f"unknown role {p.get('role')}")
    if "key_id" in p:
        found = state.key(p["key_id"])
        if not found or found[0] != p.get("user"):
            raise ValueError(f"key {p['key_id']} does not belong to {p.get('user')}")
    if kind == "restrict_role_policy" and p.get("policy_name") not in state.policies("role", p["role"]):
        raise ValueError("unknown role policy")
    if kind == "restrict_user_policy" and p.get("policy_name") not in state.policies("user", p["user"]):
        raise ValueError("unknown user policy")
    if kind == "rotate_secret" and not state.resource(p.get("secret_arn", "")):
        raise ValueError("unknown secret")


def target_for(kind: str, p: dict[str, Any]) -> str:
    return p.get("key_id") or p.get("role") or p.get("user") or p.get("secret_arn") or "incident"


class Executor:
    """Applies catalog actions to an IamState (sandbox clone or production model)."""

    def __init__(self, observed: callable, evidence: dict[str, Evidence], run_dir: Path | None) -> None:
        self.observed = observed
        self.evidence = evidence
        self.run_dir = run_dir

    def apply(self, state: IamState, a: Action, now: datetime) -> dict[str, Any]:
        p = a.params
        if a.risk == "dangerous":
            raise PermissionError("dangerous actions are never executed by Sentinel")
        match a.kind:
            case "snapshot_evidence":
                blob = json.dumps({"evidence": {k: v.model_dump(mode="json") for k, v in self.evidence.items()},
                                   "iam_state": state.d}, sort_keys=True, default=str).encode()
                digest = hashlib.sha256(blob).hexdigest()
                if self.run_dir:
                    self.run_dir.mkdir(parents=True, exist_ok=True)
                    (self.run_dir / "evidence-bundle.json").write_bytes(blob)
                state.d.setdefault("evidence_snapshots", []).append({"sha256": digest, "at": now.isoformat()})
                return {"sha256": digest, "items": len(self.evidence)}
            case "deactivate_access_key":
                _, k = state.key(p["key_id"])
                prev, k["status"] = k["status"], "Inactive"
                return {"key_id": p["key_id"], "previous_status": prev}
            case "revoke_role_sessions":
                state.roles[p["role"]]["inline_policies"]["AWSRevokeOlderSessions"] = {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*",
                                   "Condition": {"DateLessThan": {"aws:TokenIssueTime": now.isoformat()}}}]}
                return {"remove_policy": "AWSRevokeOlderSessions", "revoked_before": now.isoformat()}
            case "rotate_access_key":
                new_id = f"AKIAQ3EXAMPLEROTAT{a.attempt:02d}"
                state.add_key(p["user"], new_id, now)
                state.ci_credential["key_id"] = new_id
                _, k = state.key(p["key_id"])
                k["status"] = "Inactive"
                return {"new_key_id": new_id, "old_key_id": p["key_id"],
                        "ci_secret": f"{state.ci_credential['repository']}:{state.ci_credential['secret_name']}"}
            case "restrict_role_policy" | "restrict_user_policy":
                kind = "role" if a.kind == "restrict_role_policy" else "user"
                owner = p[kind]
                new_doc = least_privilege_policy(self.observed(owner))
                pols = state.policies(kind, owner)
                old = pols[p["policy_name"]]
                pols[p["policy_name"]] = new_doc
                a.params["new_policy"] = new_doc
                return {"previous_policy": old}
            case "rotate_secret":
                res = state.resource(p["secret_arn"])
                res["version"] = res.get("version", 1) + 1
                return {"previous_version": res["version"] - 1, "new_version": res["version"]}
        raise ValueError(f"no executor for {a.kind}")
