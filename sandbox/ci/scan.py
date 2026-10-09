"""Scan the CI repo inside the sandbox. Semgrep runs first; the regex matcher is the fallback."""

import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


def via_semgrep(repo: Path, rules: Path) -> list[dict] | None:
    if shutil.which("semgrep") is None:
        return None
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0",
           "HOME": os.environ.get("HOME") or "/tmp"}
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--disable-version-check", "--metrics=off", "--quiet", "--jobs", "1",
             "--scan-unknown-extensions", "--config", str(rules), "--json", str(repo)],
            capture_output=True, text=True, timeout=45, env=env)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode not in (0, 1):
        return None
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return None
    findings = []
    for r in data.get("results", []):
        path = Path(r["path"])
        rel = str(path.relative_to(repo)) if path.is_absolute() else r["path"]
        findings.append({
            "rule": r["check_id"].split(".")[-1],
            "path": rel,
            "line": r["start"]["line"],
            "severity": r["extra"]["severity"],
            "message": r["extra"]["message"],
            "snippet": r["extra"].get("lines", "").strip()[:240],
            "cwe": (r["extra"].get("metadata") or {}).get("cwe"),
            "engine": "semgrep",
        })
    return findings


def via_regex(repo: Path, rules: Path) -> list[dict]:
    findings = []
    for rule in yaml.safe_load(rules.read_text())["rules"]:
        rx = re.compile(rule["pattern-regex"])
        includes = rule.get("paths", {}).get("include", ["*"])
        for f in sorted(p for p in repo.rglob("*") if p.is_file()):
            if not any(fnmatch.fnmatch(f.name, g) for g in includes):
                continue
            for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
                if rx.search(line):
                    findings.append({
                        "rule": rule["id"],
                        "path": str(f.relative_to(repo)),
                        "line": i,
                        "severity": rule["severity"],
                        "message": rule["message"],
                        "snippet": line.strip()[:240],
                        "cwe": rule.get("metadata", {}).get("cwe"),
                        "engine": "builtin",
                    })
    return findings


def main() -> None:
    repo, rules = Path(sys.argv[1]), Path(sys.argv[2])
    found = via_semgrep(repo, rules)
    print(json.dumps(found if found is not None else via_regex(repo, rules)))


if __name__ == "__main__":
    main()
