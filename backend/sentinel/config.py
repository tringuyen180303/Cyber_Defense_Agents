import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

SCENARIO_DIR = ROOT / "scenario"
FIXTURES = SCENARIO_DIR / "fixtures"
CI_REPO = SCENARIO_DIR / "ci_repo"
SEMGREP_RULES = ROOT / "semgrep" / "ci-credential-rules.yml"
RUNS_DIR = ROOT / "runs"

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("SENTINEL_MODEL", "gpt-4.1")
LLM_PRICE = os.getenv("SENTINEL_LLM_PRICE", "")
CLICKHOUSE_URL = os.getenv("CLICKHOUSE_URL", "")  # e.g. http://default:@localhost:8123
OTEL_ENDPOINT = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").rstrip("/")  # e.g. http://localhost:14318
GRAFANA_URL = os.getenv("SENTINEL_GRAFANA_URL", "http://localhost:3000" if OTEL_ENDPOINT else "").rstrip("/")
ENVIRONMENT = os.getenv("SENTINEL_ENV", "demo")

# Seconds of wall-clock per replayed event, and pause between agent steps (for a watchable demo).
REPLAY_DELAY = float(os.getenv("SENTINEL_REPLAY_DELAY", "0.35"))
AGENT_PACE = float(os.getenv("SENTINEL_AGENT_PACE", "0.8"))
AUTO_APPROVE = os.getenv("SENTINEL_AUTO_APPROVE", "0") == "1"
