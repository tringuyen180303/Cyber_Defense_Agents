# Sentinel — autonomous cloud incident response that gets better every incident

Sentinel handles one incident class end to end: **a compromised CI credential in AWS IAM**. It detects the
attack in CloudTrail, investigates it with evidence-cited reasoning, maps the blast radius as an attack graph,
plans tiered remediation, proves the plan in a sandbox (replaying the attack *and* the legitimate CI workload),
executes after approval, and writes the postmortem.

A self-improvement loop then makes the next incident faster: a **Red Team** agent mutates attacks to find
evasions, a **Learner** proposes knowledge changes, and an **Evaluator** replays every scenario and only lets
through changes that improve the scorecard with zero regressions. A human approves each promotion.

## Quick start

```bash
# backend (Python 3.11+, uv)
cd backend && uv sync
uv run uvicorn sentinel.api:app --port 8000

# frontend
cd frontend && npm install && npm run dev        # http://127.0.0.1:5173
```

Click **Simulate credential attack** to replay the incident. Switch to **Self-improvement** to run red-team
rounds, review candidates and approve promotions.

Headless:

```bash
cd backend
uv run python -m sentinel.cli                                  # one incident, auto-approved, prints postmortem
uv run python -m sentinel.evaluation [--version N] [--save]    # scorecard for a knowledge version
uv run python -m sentinel.selfplay --rounds 2 --auto-approve   # red team ↔ learner self-play
uv run python -m sentinel.selfplay --reset --rounds 0          # back to hand-written knowledge v1
```

### Environment

| variable | default | |
|---|---|---|
| `OPENAI_API_KEY` | – | enables LLM reasoning; without it every agent uses deterministic offline reasoning |
| `SENTINEL_MODEL` | `gpt-4.1` | |
| `CLICKHOUSE_URL` | – | event store; in-memory otherwise (`uv sync --extra clickhouse`) |
| `SENTINEL_REPLAY_DELAY` / `SENTINEL_AGENT_PACE` | `0.35` / `0.8` | demo pacing in seconds |
| `SENTINEL_AUTO_APPROVE` | off | skip the human approval step for REVIEW actions |

Semgrep is used when the `semgrep` CLI is on `PATH`; otherwise a built-in matcher runs the same rules.

## How it works

```
CloudTrail ─▶ Normalizer ─▶ Detection (knowledge rules, noisy-OR) ─▶ Incident Commander
                                                                        │
     Investigator (tools + LLM, every claim cites evidence IDs) ◀───────┤
     Blast radius (IAM policy evaluator → attack graph)         ◀───────┤
     Planner (SAFE / REVIEW / DANGEROUS, learned playbooks)     ◀───────┤
     Verifier (sandbox clone: attack replay + app health + guardrails; ablation on failure)
     Executor (reversible actions, rollback info) ─▶ production checks ─▶ Postmortem ─▶ episodic memory
```

**Deterministic where it must be.** Detection, IAM policy evaluation, attack paths, risk tiers, verification
and execution are code. The LLM ranks hypotheses and writes narrative; any claim citing an evidence ID that
does not exist is dropped. DANGEROUS actions (e.g. deleting the IAM user) are never executed.

**Self-improvement** (`backend/sentinel/{scenarios,evaluation,redteam,learner,selfplay}.py`):

- `knowledge/versions/vN.yaml` — the only learnable surface: detector rules (feature conjunctions + weights),
  thresholds and remediation playbooks. Guardrails, risk tiers, the evaluator and the executor are not learnable.
- `scenario/specs/*.yaml` — attack and benign scenarios as declarative step lists; the Red Team writes new
  evasions to `scenario/specs/discovered/` with provenance.
- Evaluator objective (lexicographic): correct verdicts, errors, containment, prod health, sandbox attempts,
  events to detect. Any scenario that flips from correct to incorrect rejects the change.
- `knowledge/CHANGELOG.md` records every promotion with its trigger, metrics and approver;
  `knowledge/memory/incidents.jsonl` stores past incidents that the Investigator recalls by similarity.

Typical self-play from v1: the learner lowers a noisy weight (removes a false positive on a new CI runner range),
turns the sandbox repair "don't deactivate a key CI still uses — rotate it" into playbook PB-1 (plans pass the
sandbox first try), and adds rules that catch the Red Team's evasions (e.g. persistence from a known network
with no discovery phase).

## Layout

```
backend/sentinel/   agents, commander, IAM evaluator, graph, actions, verification, learning loop, API
frontend/src/       React dashboard (incident view + self-improvement view)
scenario/           IAM fixture, baseline generator, scenario specs, planted-leak CI repo
semgrep/            CI credential leak rules
knowledge/          versioned knowledge, scorecards, changelog, episodic memory
```
