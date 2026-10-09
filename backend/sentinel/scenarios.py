"""Scenario specs (YAML) → CloudTrail records. Used for the demo, the eval suite and red-team variants."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from . import config
from .synth import CI_KEY, GITHUB_IPS, UA, Synth, iam_user

SPEC_DIR = config.SCENARIO_DIR / "specs"
DISCOVERED_DIR = SPEC_DIR / "discovered"


@dataclass
class Scenario:
    id: str
    label: str  # "attack" | "benign"
    description: str
    spec: dict[str, Any]
    records: list[dict[str, Any]] = field(default_factory=list)
    attacker_event_ids: set[str] = field(default_factory=set)
    source: str = "suite"

    @property
    def expect_incident(self) -> bool:
        return self.spec.get("expect", {}).get("incident", self.label == "attack")


def _ip(v: str | None, default: str) -> str:
    if v is None:
        return default
    return {"github": GITHUB_IPS[1], "github2": GITHUB_IPS[3]}.get(v, v)


def _ua(v: str | None, default: str) -> str:
    if v is None:
        return default
    return UA.get(v, v)


def build(spec: dict[str, Any]) -> Scenario:
    syn = Synth(seed=spec.get("seed", 7))
    start = datetime.fromisoformat(str(spec.get("start", "2026-10-07T02:25:00+00:00")).replace("Z", "+00:00"))
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    atk = spec.get("attacker", {})
    a_ip, a_ua = _ip(atk.get("ip"), "45.137.21.9"), _ua(atk.get("ua"), UA["kali"])
    creds: dict[str, dict] = {"leaked": iam_user("ci-deployer", CI_KEY)}
    t = start
    out: list[dict] = []
    attacker_ids: set[str] = set()

    for step in spec["steps"]:
        if "at" in step:
            hh, mm, ss = (int(x) for x in str(step["at"]).split(":"))
            t = start.replace(hour=hh, minute=mm, second=ss)
        else:
            t = t + timedelta(seconds=float(step.get("after", 20)))
        do = step.get("do", "call")
        count, spacing = int(step.get("count", 1)), float(step.get("spacing", 3))

        if do == "ci_run":
            out += syn.ci_run(t, step.get("run_id", 4900), _ip(step.get("ip"), None) if step.get("ip") else None,
                              step.get("bucket", "build-artifacts"))
            continue
        if do == "api_read":
            for i in range(count):
                out.append(syn.api_read(t + timedelta(seconds=i * spacing)))
            continue
        if do == "admin_review":
            out += syn.admin_review(t)
            continue

        ident = creds.get(step.get("as", "leaked"))
        if ident is None:
            raise ValueError(f"step uses credential '{step.get('as')}' before it exists: {step}")
        ip, ua = _ip(step.get("ip"), a_ip), _ua(step.get("ua"), a_ua)
        svc, name = step["api"].split(":", 1)
        err = step.get("error")
        hostile = spec.get("label", "attack") == "attack" and not step.get("legit")
        before = len(out)
        for i in range(count):
            tt = t + timedelta(seconds=i * spacing)
            if name == "CreateAccessKey":
                key = step.get("key_id") or syn.access_key()
                out.append(syn.record(tt, name, ident, ip, ua, service=svc, req={"userName": "ci-deployer"},
                                      resp={"accessKey": {"userName": "ci-deployer", "accessKeyId": key,
                                                          "status": "Active", "createDate": tt.isoformat()}}))
                creds["minted"] = iam_user("ci-deployer", key)
            elif name == "AssumeRole":
                rec, sess = syn.assume_role(tt, ident, ip, ua, step.get("role", "ci-deploy-role"),
                                            step.get("session_name", "gha-debug"), step.get("session_key"))
                out.append(rec)
                creds["session"] = sess
            elif name == "GetSecretValue":
                out.append(syn.secret_read(tt, ident, ip, ua, step["secret"], error=err))
            elif svc == "s3" and name in ("GetObject", "PutObject"):
                keys = step.get("keys") or [f"{step.get('prefix', 'data')}/{syn.rng.randint(100, 9999)}.bin"
                                            for _ in range(count)]
                out.append(syn.record(tt, name, ident, ip, ua, service=svc, error=err,
                                      req={"bucketName": step["bucket"], "key": keys[i % len(keys)]}))
            elif svc == "s3" and name == "ListObjects":
                out.append(syn.record(tt, name, ident, ip, ua, service=svc, req={"bucketName": step["bucket"]},
                                      error=err))
            else:
                req = {k: step[k] for k in ("userName", "roleName", "policyName") if k in step} or None
                out.append(syn.record(tt, name, ident, ip, ua, service=svc, req=req, error=err))
        if hostile:
            attacker_ids.update(r["eventID"] for r in out[before:])
        t = t + timedelta(seconds=(count - 1) * spacing)

    out.sort(key=lambda r: r["eventTime"])
    return Scenario(id=spec["id"], label=spec.get("label", "attack"), description=spec.get("description", ""),
                    spec=spec, records=out, attacker_event_ids=attacker_ids)


def load(path: Path, source: str = "suite") -> Scenario:
    sc = build(yaml.safe_load(path.read_text()))
    sc.source = source
    return sc


def load_suite(include_discovered: bool = True) -> list[Scenario]:
    out = [load(p) for p in sorted(SPEC_DIR.glob("*.yaml"))]
    if include_discovered and DISCOVERED_DIR.exists():
        out += [load(p, "red-team") for p in sorted(DISCOVERED_DIR.glob("*.yaml"))]
    return out


def save_discovered(spec: dict[str, Any]) -> Path:
    DISCOVERED_DIR.mkdir(parents=True, exist_ok=True)
    p = DISCOVERED_DIR / f"{spec['id']}.yaml"
    p.write_text(yaml.safe_dump(spec, sort_keys=False, width=110))
    return p


def clone_spec(spec: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(spec)
