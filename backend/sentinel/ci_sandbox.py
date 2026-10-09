"""Run the CI job inside Docker so the agent can see what it would do without touching the host or the network.

The container has no network, a read-only root, no capabilities, and no Docker socket. The repo is mounted
read-only and copied onto a tmpfs. aws, npm and docker are stubs that record the command and return fixture
data, so a job that would have called AWS is observed instead of executed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from . import config

IMAGE = "sentinel-ci-sandbox:local"
SANDBOX_DIR = config.ROOT / "sandbox" / "ci"
_cache: dict[tuple[str, str], dict[str, Any]] = {}


def label() -> str:
    if shutil.which("docker") and config.CI_SANDBOX:
        return "Docker CI sandbox (Semgrep, network off)"
    from .integrations import semgrep_label
    return semgrep_label()


def docker_argv(repo: Path, rules: Path) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "256",
        "--memory", "2g",
        "--cpus", "1",
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,size=64m,mode=1777",
        "--user", "65534:65534",
        "-v", f"{repo.resolve()}:/work:ro",
        "-v", f"{rules.resolve()}:/opt/rules.yml:ro",
        IMAGE,
    ]


def context(repo: Path = config.CI_REPO, rules: Path = config.SEMGREP_RULES) -> dict[str, Any]:
    key = (str(repo.resolve()), str(rules.resolve()))
    if key not in _cache:
        _cache[key] = _run(repo, rules) if _enabled() and _ensure_image() else _static(repo, rules)
    return _cache[key]


def _enabled() -> bool:
    return shutil.which("docker") is not None and config.CI_SANDBOX


def _ensure_image() -> bool:
    have = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True)
    if have.returncode == 0:
        return True
    built = subprocess.run(["docker", "build", "-t", IMAGE, str(SANDBOX_DIR)], capture_output=True, text=True,
                           timeout=300)
    return built.returncode == 0


def _run(repo: Path, rules: Path) -> dict[str, Any]:
    try:
        proc = subprocess.run(docker_argv(repo, rules), capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return _static(repo, rules)
    if proc.returncode != 0:
        return _static(repo, rules)
    out = proc.stdout
    trace = _between(out, "TRACE_BEGIN", "TRACE_END")
    raw = _between(out, "SEMGREP_BEGIN", "SEMGREP_END").strip()
    try:
        findings = json.loads(raw.splitlines()[-1]) if raw else []
    except json.JSONDecodeError:
        return _static(repo, rules)
    return _pack("docker", "none", findings, [ln.strip() for ln in trace.splitlines() if ln.strip()])


def _static(repo: Path, rules: Path) -> dict[str, Any]:
    from .integrations import _fallback_scan

    trace = []
    for f in sorted(p for p in repo.rglob("*") if p.is_file() and p.suffix in {".sh", ".yml", ".yaml"}):
        for line in f.read_text(errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("#") or not re.search(r"\b(aws|npm|docker)\b", s):
                continue
            trace.append(s[:180])
    return _pack("static", "not-executed", _fallback_scan(repo, rules), trace[:40])


def _pack(engine: str, network: str, findings: list[dict], trace: list[str]) -> dict[str, Any]:
    return {"engine": engine, "network": network, "image": IMAGE if engine == "docker" else None,
            "findings": findings, "trace": trace, "calls": _calls(trace)}


def _calls(trace: list[str]) -> list[str]:
    seen: list[str] = []
    for line in trace:
        head = " ".join(line.split()[:3])
        if head not in seen:
            seen.append(head)
    return seen


def _between(text: str, start: str, end: str) -> str:
    if start not in text or end not in text:
        return ""
    return text.split(start, 1)[1].split(end, 1)[0]
