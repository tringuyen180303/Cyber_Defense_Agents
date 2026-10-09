"""Generate CloudTrail-shaped fixtures for the compromised-CI-credential scenario.

Outputs (in scenario/fixtures/):
  baseline_events.jsonl   30 days of normal activity used for behavioral baselines
  incident_events.json    the demo incident window, built from specs/attack-ci-key-classic.yaml
  deployments.json        deploy log used by the investigator
  threat_intel.json       offline IP reputation data

Usage: python scenario/generate_fixtures.py [--scale N]
"""

from __future__ import annotations

import argparse
import sys
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNT = "111122223333"
REGION = "us-west-2"
OUT = Path(__file__).parent / "fixtures"

CI_KEY = "AKIAQ3EXAMPLECIKEY01"
ATTACKER_KEY = "AKIAQ3EXAMPLEATTK7XZ"
ATTACKER_SESSION = "ASIAQ3EXAMPLESESS9FQ"
ATTACKER_IP = "45.137.21.9"
ATTACKER_UA = "Boto3/1.34.11 md/Botocore#1.34.11 ua/2.0 os/linux#6.5.0-kali3-amd64 lang/python#3.11.8"
GITHUB_IPS = ["4.148.12.34", "20.42.8.17", "52.225.70.9", "13.105.49.4", "172.183.51.20"]
CI_UA = "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1016-azure exe/x86_64.ubuntu.22 exec-env/GitHub-Actions"
API_UA = "aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 api/s3#1.58.2"
ADMIN_UA = "aws-cli/2.17.4 Python/3.11.9 Darwin/24.6.0 source/arm64"

INCIDENT_START = datetime(2026, 10, 7, 2, 25, 0, tzinfo=timezone.utc)

SECRET_NPM = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:ci/npm-token-Ab12Cd"
SECRET_DB = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/db-password-Ef34Gh"

rng = random.Random(42)


def ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def iam_user(name: str, key: str) -> dict:
    return {
        "type": "IAMUser",
        "principalId": "AIDAQ3EXAMPLE" + name.upper().replace("-", "")[:7],
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "accessKeyId": key,
        "userName": name,
    }


def role_session(role: str, session_key: str, session_name: str, issued: datetime) -> dict:
    return {
        "type": "AssumedRole",
        "principalId": f"AROAQ3EXAMPLE{role.upper().replace('-', '')[:6]}:{session_name}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session_name}",
        "accountId": ACCOUNT,
        "accessKeyId": session_key,
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": f"AROAQ3EXAMPLE{role.upper().replace('-', '')[:6]}",
                "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                "accountId": ACCOUNT,
                "userName": role,
            },
            "attributes": {"creationDate": ts(issued), "mfaAuthenticated": "false"},
        },
    }


def record(t, source, name, identity, ip, ua, req=None, resp=None, error=None, read_only=True, resources=None,
           data_event=False):
    rec = {
        "eventVersion": "1.09",
        "userIdentity": identity,
        "eventTime": ts(t),
        "eventSource": source,
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": req,
        "responseElements": resp,
        "requestID": str(uuid.UUID(int=rng.getrandbits(128))),
        "eventID": str(uuid.UUID(int=rng.getrandbits(128))),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": not data_event,
        "recipientAccountId": ACCOUNT,
        "eventCategory": "Data" if data_event else "Management",
    }
    if error:
        rec["errorCode"] = error
        rec["errorMessage"] = f"User: {identity['arn']} is not authorized to perform this operation"
    if resources:
        rec["resources"] = resources
    return rec


def session_key() -> str:
    return "ASIAQ3" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(14))


def ci_run(t: datetime, run_id: int, ip: str | None = None) -> list[dict]:
    ip = ip or rng.choice(GITHUB_IPS)
    sk = session_key()
    sname = f"gha-{run_id}"
    sess = role_session("ci-deploy-role", sk, sname, t)
    sha = "%040x" % rng.getrandbits(160)
    events = [
        record(t, "sts.amazonaws.com", "AssumeRole", iam_user("ci-deployer", CI_KEY), ip, CI_UA,
               req={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/ci-deploy-role", "roleSessionName": sname},
               resp={"credentials": {"accessKeyId": sk, "expiration": ts(t + timedelta(hours=1))},
                     "assumedRoleUser": {"arn": sess["arn"]}}),
        record(t + timedelta(seconds=6), "secretsmanager.amazonaws.com", "GetSecretValue", sess, ip, CI_UA,
               req={"secretId": "ci/npm-token"}, resources=[{"ARN": SECRET_NPM, "type": "AWS::SecretsManager::Secret"}]),
        record(t + timedelta(seconds=94), "s3.amazonaws.com", "PutObject", sess, ip, CI_UA,
               req={"bucketName": "build-artifacts", "key": f"builds/{sha[:12]}.tar.gz"}, read_only=False,
               data_event=True),
        record(t + timedelta(seconds=101), "ecr.amazonaws.com", "GetAuthorizationToken", sess, ip, CI_UA),
        record(t + timedelta(seconds=118), "ecr.amazonaws.com", "PutImage", sess, ip, CI_UA,
               req={"repositoryName": "sentinel-api", "imageTag": sha[:12]}, read_only=False),
    ]
    return events


def api_read(t: datetime) -> dict:
    sess = role_session("prod-api-role", "ASIAQ3PRODAPITASK001", "ecs-task-7f3a", t - timedelta(minutes=20))
    doc = rng.choice(["invoices", "contracts", "kyc"]) + f"/2026/{rng.randint(1000, 9999)}.pdf"
    return record(t, "s3.amazonaws.com", "GetObject", sess, f"10.0.{rng.randint(1, 3)}.{rng.randint(10, 250)}",
                  API_UA, req={"bucketName": "customer-documents", "key": doc}, data_event=True)


def admin_activity(t: datetime) -> list[dict]:
    who = iam_user("alice-admin", "AKIAQ3EXAMPLEALICE01")
    ip = "198.51.100.23"
    return [
        record(t, "iam.amazonaws.com", "ListUsers", who, ip, ADMIN_UA),
        record(t + timedelta(seconds=20), "iam.amazonaws.com", "ListRoles", who, ip, ADMIN_UA),
    ]


def baseline(scale: int) -> list[dict]:
    events: list[dict] = []
    start = INCIDENT_START - timedelta(days=30)
    run_id = 4100
    for day in range(30):
        d = start + timedelta(days=day)
        runs = rng.randint(2, 4) if d.weekday() >= 5 else rng.randint(5, 9)
        for _ in range(runs):
            run_id += 1
            t = d.replace(hour=rng.randint(14, 23), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            events += ci_run(t, run_id)
        for _ in range(60 * scale):
            events.append(api_read(d + timedelta(seconds=rng.randint(0, 86399))))
        if day % 7 == 2:
            events += admin_activity(d.replace(hour=17, minute=12))
    events.sort(key=lambda e: e["eventTime"])
    return events


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scale", type=int, default=1, help="multiplier for baseline API traffic volume")
    args = p.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    base = baseline(args.scale)
    with open(OUT / "baseline_events.jsonl", "w") as f:
        for e in base:
            f.write(json.dumps(e) + "\n")

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from sentinel.scenarios import load

    inc = load(Path(__file__).parent / "specs" / "attack-ci-key-classic.yaml").records
    (OUT / "incident_events.json").write_text(json.dumps(inc, indent=1))
    (OUT / "deployments.json").write_text(json.dumps([
        {"id": "deploy-4819", "service": "sentinel-api", "time": "2026-10-06T21:48:12Z", "actor": "github-actions",
         "commit": "9c1e2fa", "change_ticket": "CHG-2291"},
        {"id": "deploy-4821", "service": "sentinel-api", "time": "2026-10-07T02:27:10Z", "actor": "github-actions",
         "commit": "b77d04e", "change_ticket": "CHG-2297"},
    ], indent=1))
    (OUT / "threat_intel.json").write_text(json.dumps({
        ATTACKER_IP: {"asn": "AS64511", "org": "ExampleVPS Hosting (fictional)", "country": "NL",
                      "category": "hosting/VPS", "blocklists": [], "first_seen_by_feeds": None,
                      "note": "No reputation data; hosting-provider address space"},
        **{ip: {"asn": "AS8075", "org": "Microsoft Azure (GitHub Actions runners)", "country": "US",
                "category": "ci-runner", "blocklists": []} for ip in GITHUB_IPS},
    }, indent=1))
    print(f"baseline events: {len(base)}  incident events: {len(inc)}")


if __name__ == "__main__":
    main()
