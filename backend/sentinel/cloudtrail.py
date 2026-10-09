"""CloudTrail parsing: maps raw records to IAM actions/resources and tracks credential lineage."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import Event

SERVICE_PREFIX = {
    "iam.amazonaws.com": "iam",
    "sts.amazonaws.com": "sts",
    "s3.amazonaws.com": "s3",
    "secretsmanager.amazonaws.com": "secretsmanager",
    "ecr.amazonaws.com": "ecr",
}

# CloudTrail eventName -> IAM action name where they differ.
ACTION_ALIASES = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "ListObjects"): "s3:ListBucket",
    ("s3", "ListObjectsV2"): "s3:ListBucket",
}


def parse_time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _resource(rec: dict[str, Any], service: str, account: str, region: str) -> str:
    req = rec.get("requestParameters") or {}
    name = rec["eventName"]
    if service == "s3":
        bucket = req.get("bucketName")
        if not bucket:
            return "*"
        return f"arn:aws:s3:::{bucket}/{req['key']}" if req.get("key") else f"arn:aws:s3:::{bucket}"
    if service == "secretsmanager":
        for r in rec.get("resources") or []:
            return r["ARN"]
        return f"arn:aws:secretsmanager:{region}:{account}:secret:{req.get('secretId', '*')}"
    if service == "sts" and name == "AssumeRole":
        return req.get("roleArn", "*")
    if service == "iam":
        if "userName" in req:
            return f"arn:aws:iam::{account}:user/{req['userName']}"
        if "roleName" in req:
            return f"arn:aws:iam::{account}:role/{req['roleName']}"
        return "*"
    if service == "ecr" and req.get("repositoryName"):
        return f"arn:aws:ecr:{region}:{account}:repository/{req['repositoryName']}"
    return "*"


class Normalizer:
    """Stateful: remembers which long-lived key minted each STS session so role activity
    can be attributed back to the originating IAM user and access key."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}

    def __call__(self, rec: dict[str, Any], evidence_id: str | None = None) -> Event:
        ident = rec["userIdentity"]
        service = SERVICE_PREFIX.get(rec["eventSource"], rec["eventSource"].split(".")[0])
        name = rec["eventName"]
        account = rec.get("recipientAccountId", ident.get("accountId", ""))
        region = rec.get("awsRegion", "")
        key = ident.get("accessKeyId", "")
        t = parse_time(rec["eventTime"])

        if ident["type"] == "AssumedRole":
            principal = ident["sessionContext"]["sessionIssuer"]["userName"]
            lineage = self.sessions.get(key, {})
            origin_user, origin_key = lineage.get("user"), lineage.get("key")
            issued = lineage.get("issued") or parse_time(ident["sessionContext"]["attributes"]["creationDate"])
        else:
            principal = ident.get("userName", ident.get("arn", "unknown"))
            origin_user, origin_key, issued = principal, key, None

        if name == "AssumeRole" and not rec.get("errorCode"):
            creds = (rec.get("responseElements") or {}).get("credentials", {})
            if creds.get("accessKeyId"):
                self.sessions[creds["accessKeyId"]] = {"user": origin_user, "key": origin_key, "issued": t}

        return Event(
            id=rec["eventID"],
            evidence_id=evidence_id,
            time=t,
            source=service,
            name=name,
            iam_action=ACTION_ALIASES.get((service, name), f"{service}:{name}"),
            resource=_resource(rec, service, account, region),
            principal=principal,
            principal_type=ident["type"],
            access_key=key,
            origin_user=origin_user,
            origin_key=origin_key,
            session_issued=issued,
            ip=rec.get("sourceIPAddress", ""),
            user_agent=rec.get("userAgent", ""),
            error=rec.get("errorCode"),
            raw=rec,
        )


def short_resource(arn: str) -> str:
    if arn == "*":
        return "*"
    if arn.startswith("arn:aws:s3:::"):
        return "s3://" + arn.removeprefix("arn:aws:s3:::")
    tail = arn.split(":", 5)[-1]
    if ":secret:" in arn:
        return "secret:" + arn.split(":secret:")[1].rsplit("-", 1)[0]
    return tail
