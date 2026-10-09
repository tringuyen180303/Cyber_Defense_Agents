"""Synthetic CloudTrail record builders shared by the baseline generator and the scenario engine."""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta

ACCOUNT = "111122223333"
REGION = "us-west-2"

CI_KEY = "AKIAQ3EXAMPLECIKEY01"
ADMIN_KEY = "AKIAQ3EXAMPLEALICE01"
ATTACKER_IP = "45.137.21.9"
GITHUB_IPS = ["4.148.12.34", "20.42.8.17", "52.225.70.9", "13.105.49.4", "172.183.51.20"]
ADMIN_IP = "198.51.100.23"

UA = {
    "kali": "Boto3/1.34.11 md/Botocore#1.34.11 ua/2.0 os/linux#6.5.0-kali3-amd64 lang/python#3.11.8",
    "ci": "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1016-azure exe/x86_64.ubuntu.22 exec-env/GitHub-Actions",
    "api": "aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 api/s3#1.58.2",
    "admin": "aws-cli/2.17.4 Python/3.11.9 Darwin/24.6.0 source/arm64",
}

SECRETS = {
    "ci/npm-token": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:ci/npm-token-Ab12Cd",
    "prod/db-password": f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:prod/db-password-Ef34Gh",
}

SERVICE_SOURCE = {"iam": "iam.amazonaws.com", "sts": "sts.amazonaws.com", "s3": "s3.amazonaws.com",
                  "secretsmanager": "secretsmanager.amazonaws.com", "ecr": "ecr.amazonaws.com"}
DATA_EVENTS = {"GetObject", "PutObject", "ListObjects"}
WRITE_EVENTS = {"CreateAccessKey", "PutObject", "PutImage", "UpdateAccessKey", "DeleteAccessKey"}


def ts(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def iam_user(name: str, key: str) -> dict:
    return {"type": "IAMUser", "principalId": "AIDAQ3EXAMPLE" + name.upper().replace("-", "")[:7],
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT, "accessKeyId": key,
            "userName": name}


def role_session(role: str, session_key: str, session_name: str, issued: datetime) -> dict:
    rid = "AROAQ3EXAMPLE" + role.upper().replace("-", "")[:6]
    return {
        "type": "AssumedRole", "principalId": f"{rid}:{session_name}",
        "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session_name}", "accountId": ACCOUNT,
        "accessKeyId": session_key,
        "sessionContext": {
            "sessionIssuer": {"type": "Role", "principalId": rid, "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}",
                              "accountId": ACCOUNT, "userName": role},
            "attributes": {"creationDate": ts(issued), "mfaAuthenticated": "false"},
        },
    }


class Synth:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def uid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128)))

    def session_key(self) -> str:
        return "ASIAQ3" + "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(14))

    def access_key(self) -> str:
        return "AKIAQ3" + "".join(self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(14))

    def record(self, t, name, identity, ip, ua, service=None, req=None, resp=None, error=None, resources=None):
        service = service or {"GetCallerIdentity": "sts", "AssumeRole": "sts", "GetSecretValue": "secretsmanager",
                              "PutImage": "ecr", "GetAuthorizationToken": "ecr"}.get(name) or \
            ("s3" if name in DATA_EVENTS | {"ListBuckets"} else "iam")
        rec = {
            "eventVersion": "1.09", "userIdentity": identity, "eventTime": ts(t),
            "eventSource": SERVICE_SOURCE[service], "eventName": name, "awsRegion": REGION,
            "sourceIPAddress": ip, "userAgent": ua, "requestParameters": req, "responseElements": resp,
            "requestID": self.uid(), "eventID": self.uid(), "readOnly": name not in WRITE_EVENTS,
            "eventType": "AwsApiCall", "managementEvent": name not in DATA_EVENTS, "recipientAccountId": ACCOUNT,
            "eventCategory": "Data" if name in DATA_EVENTS else "Management",
        }
        if error:
            rec["errorCode"] = error
            rec["errorMessage"] = f"User: {identity['arn']} is not authorized to perform this operation"
        if resources:
            rec["resources"] = resources
        return rec

    def assume_role(self, t, caller: dict, ip, ua, role, session_name, session_key=None):
        sk = session_key or self.session_key()
        sess = role_session(role, sk, session_name, t)
        rec = self.record(t, "AssumeRole", caller, ip, ua,
                          req={"roleArn": f"arn:aws:iam::{ACCOUNT}:role/{role}", "roleSessionName": session_name},
                          resp={"credentials": {"accessKeyId": sk, "expiration": ts(t + timedelta(hours=1))},
                                "assumedRoleUser": {"arn": sess["arn"]}})
        return rec, sess

    def secret_read(self, t, identity, ip, ua, name, error=None):
        return self.record(t, "GetSecretValue", identity, ip, ua, req={"secretId": name}, error=error,
                           resources=[{"ARN": SECRETS[name], "type": "AWS::SecretsManager::Secret"}])

    def ci_run(self, t: datetime, run_id: int, ip: str | None = None, bucket: str = "build-artifacts") -> list[dict]:
        ip = ip or self.rng.choice(GITHUB_IPS)
        ar, sess = self.assume_role(t, iam_user("ci-deployer", CI_KEY), ip, UA["ci"], "ci-deploy-role",
                                    f"gha-{run_id}")
        sha = "%040x" % self.rng.getrandbits(160)
        return [
            ar,
            self.secret_read(t + timedelta(seconds=6), sess, ip, UA["ci"], "ci/npm-token"),
            self.record(t + timedelta(seconds=94), "PutObject", sess, ip, UA["ci"],
                        req={"bucketName": bucket, "key": f"builds/{sha[:12]}.tar.gz"}),
            self.record(t + timedelta(seconds=101), "GetAuthorizationToken", sess, ip, UA["ci"]),
            self.record(t + timedelta(seconds=118), "PutImage", sess, ip, UA["ci"],
                        req={"repositoryName": "sentinel-api", "imageTag": sha[:12]}),
        ]

    def api_read(self, t: datetime) -> dict:
        sess = role_session("prod-api-role", "ASIAQ3PRODAPITASK001", "ecs-task-7f3a", t - timedelta(minutes=20))
        doc = self.rng.choice(["invoices", "contracts", "kyc"]) + f"/2026/{self.rng.randint(1000, 9999)}.pdf"
        return self.record(t, "GetObject", sess, f"10.0.{self.rng.randint(1, 3)}.{self.rng.randint(10, 250)}",
                           UA["api"], req={"bucketName": "customer-documents", "key": doc})

    def admin_review(self, t: datetime) -> list[dict]:
        who = iam_user("alice-admin", ADMIN_KEY)
        return [self.record(t, "ListUsers", who, ADMIN_IP, UA["admin"]),
                self.record(t + timedelta(seconds=20), "ListRoles", who, ADMIN_IP, UA["admin"])]
