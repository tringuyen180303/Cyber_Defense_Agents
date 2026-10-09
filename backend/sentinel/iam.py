"""IAM state model and a deterministic policy evaluator.

Implements the parts of AWS's evaluation logic this scenario depends on: explicit deny > allow > implicit
deny, wildcard matching for actions/resources, role trust policies, and the condition operators used by
AWS session revocation (DateLessThan on aws:TokenIssueTime) and IP restrictions. Note STS sessions stay valid
after the access key that minted them is deactivated, which is why session revocation is a separate action.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from fnmatch import fnmatchcase
from typing import Any

from . import config
from .cloudtrail import parse_time


@dataclass
class Decision:
    allowed: bool
    reason: str
    policy: str | None = None
    sid: str | None = None


@dataclass
class Caller:
    key_id: str
    kind: str  # "user" | "session"
    name: str  # user or role name
    arn: str
    issued: datetime | None = None


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


class IamState:
    def __init__(self, data: dict[str, Any]) -> None:
        self.d = data
        self.d.setdefault("sessions", {})

    @classmethod
    def load(cls) -> IamState:
        return cls(json.loads((config.FIXTURES / "iam_state.json").read_text()))

    def clone(self) -> IamState:
        return IamState(copy.deepcopy(self.d))

    @property
    def account(self) -> str:
        return self.d["account_id"]

    @property
    def users(self) -> dict[str, Any]:
        return self.d["users"]

    @property
    def roles(self) -> dict[str, Any]:
        return self.d["roles"]

    @property
    def resources(self) -> list[dict[str, Any]]:
        return self.d["resources"]

    @property
    def ci_credential(self) -> dict[str, Any]:
        return self.d["ci_credential"]

    def resource(self, arn: str) -> dict[str, Any] | None:
        return next((r for r in self.resources if r["arn"] == arn), None)

    def key(self, key_id: str) -> tuple[str, dict[str, Any]] | None:
        for uname, u in self.users.items():
            for k in u["access_keys"]:
                if k["id"] == key_id:
                    return uname, k
        return None

    def add_key(self, user: str, key_id: str, created: datetime) -> None:
        self.users[user]["access_keys"].append({"id": key_id, "status": "Active", "created": created.isoformat()})

    def register_session(self, key_id: str, role: str, issued: datetime, origin_user: str | None,
                         origin_key: str | None) -> None:
        self.d["sessions"][key_id] = {"role": role, "issued": issued.isoformat(),
                                      "expires": (issued + timedelta(hours=1)).isoformat(),
                                      "origin_user": origin_user, "origin_key": origin_key}

    def policies(self, kind: str, name: str) -> dict[str, dict[str, Any]]:
        entity = (self.users if kind == "user" else self.roles).get(name, {})
        return entity.get("inline_policies", {})

    # ---- authentication -------------------------------------------------------------------------

    def authenticate(self, key_id: str, now: datetime) -> Caller | str:
        if key_id.startswith("ASIA"):
            s = self.d["sessions"].get(key_id)
            if not s:
                return "InvalidClientTokenId: unknown session"
            if parse_time(s["expires"]) <= now:
                return "ExpiredToken"
            role = self.roles[s["role"]]
            return Caller(key_id, "session", s["role"], role["arn"], parse_time(s["issued"]))
        found = self.key(key_id)
        if not found:
            return "InvalidClientTokenId: unknown access key"
        uname, k = found
        if k["status"] != "Active":
            return "InvalidClientTokenId: access key is inactive"
        return Caller(key_id, "user", uname, self.users[uname]["arn"])

    # ---- authorization --------------------------------------------------------------------------

    def evaluate_caller(self, c: Caller, action: str, resource: str, now: datetime,
                        source_ip: str | None = None) -> Decision:
        if action == "sts:GetCallerIdentity":
            return Decision(True, "GetCallerIdentity requires only valid credentials")
        ctx = {"aws:CurrentTime": now, "aws:SourceIp": source_ip}
        if c.issued:
            ctx["aws:TokenIssueTime"] = c.issued
        allow: Decision | None = None
        for pname, doc in self.policies(c.kind if c.kind == "user" else "role", c.name).items():
            for st in _as_list(doc["Statement"]):
                if not _matches(st, action, resource, ctx):
                    continue
                if st["Effect"] == "Deny":
                    return Decision(False, f"explicit deny in {pname}", pname, st.get("Sid"))
                allow = allow or Decision(True, f"allowed by {pname}", pname, st.get("Sid"))
        if action == "sts:AssumeRole" and allow:
            role = next((r for r in self.roles.values() if r["arn"] == resource), None)
            if not role or c.arn not in role.get("trust", {}).get("AWS", []):
                return Decision(False, "role trust policy does not allow caller")
        return allow or Decision(False, "implicit deny (no matching allow)")

    def evaluate(self, key_id: str, action: str, resource: str, now: datetime,
                 source_ip: str | None = None) -> Decision:
        c = self.authenticate(key_id, now)
        if isinstance(c, str):
            return Decision(False, c)
        return self.evaluate_caller(c, action, resource, now, source_ip)

    def assume_role(self, key_id: str, role: str, now: datetime, session_key: str) -> Decision:
        role_arn = self.roles[role]["arn"]
        d = self.evaluate(key_id, "sts:AssumeRole", role_arn, now)
        if d.allowed:
            found = self.key(key_id)
            self.register_session(session_key, role, now, found[0] if found else None, key_id)
        return d


def _matches(st: dict[str, Any], action: str, resource: str, ctx: dict[str, Any]) -> bool:
    if not any(fnmatchcase(action.lower(), a.lower()) for a in _as_list(st.get("Action", []))):
        return False
    if not any(fnmatchcase(resource, r) for r in _as_list(st.get("Resource", []))):
        return False
    return _conditions(st.get("Condition", {}), ctx)


def _conditions(cond: dict[str, Any], ctx: dict[str, Any]) -> bool:
    for op, kv in cond.items():
        for key, expected in kv.items():
            actual = ctx.get(key)
            if actual is None:
                return False
            vals = _as_list(expected)
            if op in ("DateLessThan", "DateGreaterThan"):
                bound = parse_time(vals[0])
                if (op == "DateLessThan" and not actual < bound) or (op == "DateGreaterThan" and not actual > bound):
                    return False
            elif op in ("IpAddress", "NotIpAddress"):
                inside = any(ipaddress.ip_address(actual) in ipaddress.ip_network(v, strict=False) for v in vals)
                if inside != (op == "IpAddress"):
                    return False
            elif op == "StringEquals":
                if actual not in vals:
                    return False
            elif op == "StringLike":
                if not any(fnmatchcase(str(actual), v) for v in vals):
                    return False
            else:
                return False
    return True


def statement_allows(doc: dict[str, Any], action: str, resource: str) -> bool:
    """Policy-local check used for graph edges (ignores other policies and conditions)."""
    return any(st["Effect"] == "Allow" and _matches({**st, "Condition": {}}, action, resource, {})
               for st in _as_list(doc["Statement"]))
