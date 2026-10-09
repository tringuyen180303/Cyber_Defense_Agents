"""External evidence sources: Semgrep code scanning and IP threat intelligence."""

from __future__ import annotations

import fnmatch
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import yaml

from . import config


def semgrep_label() -> str:
    return "Semgrep CLI" if shutil.which("semgrep") else "Semgrep rules (built-in matcher)"


def scan_ci_repo(repo: Path = config.CI_REPO, rules: Path = config.SEMGREP_RULES) -> list[dict[str, Any]]:
    if shutil.which("semgrep"):
        try:
            out = subprocess.run(
                ["semgrep", "--config", str(rules), "--json", "--metrics=off", "--quiet", "--scan-unknown-extensions",
                 str(repo)], capture_output=True, text=True, timeout=120)
            data = json.loads(out.stdout)
            return [{
                "rule": r["check_id"].split(".")[-1],
                "path": str(Path(r["path"]).relative_to(repo)) if Path(r["path"]).is_absolute() else
                str(Path(r["path"]).resolve().relative_to(repo.resolve())),
                "line": r["start"]["line"],
                "severity": r["extra"]["severity"],
                "message": r["extra"]["message"],
                "snippet": r["extra"].get("lines", "").strip(),
                "cwe": r["extra"].get("metadata", {}).get("cwe"),
                "engine": "semgrep",
            } for r in data.get("results", [])]
        except Exception:  # noqa: BLE001
            pass
    return _fallback_scan(repo, rules)


def _fallback_scan(repo: Path, rules: Path) -> list[dict[str, Any]]:
    findings = []
    for rule in yaml.safe_load(rules.read_text())["rules"]:
        rx = re.compile(rule["pattern-regex"])
        includes = rule.get("paths", {}).get("include", ["*"])
        for f in sorted(p for p in repo.rglob("*") if p.is_file()):
            if not any(fnmatch.fnmatch(f.name, g) for g in includes):
                continue
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if rx.search(line):
                    findings.append({"rule": rule["id"], "path": str(f.relative_to(repo)), "line": i,
                                     "severity": rule["severity"], "message": rule["message"],
                                     "snippet": line.strip(), "cwe": rule.get("metadata", {}).get("cwe"),
                                     "engine": "builtin"})
    return findings


_intel: dict[str, Any] | None = None


def lookup_ip(ip: str) -> dict[str, Any]:
    global _intel
    if _intel is None:
        _intel = json.loads((config.FIXTURES / "threat_intel.json").read_text())
    return {"ip": ip, **_intel.get(ip, {"asn": None, "org": None, "category": "unknown", "blocklists": [],
                                         "note": "No data"})}
