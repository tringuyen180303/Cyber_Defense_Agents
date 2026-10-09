from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Risk = Literal["safe", "review", "dangerous"]
ActionStatus = Literal[
    "proposed", "sandbox_pass", "sandbox_fail", "awaiting_approval", "approved",
    "executed", "blocked", "superseded", "rolled_back",
]
Phase = Literal["idle", "replaying", "investigating", "verifying", "awaiting_approval", "executing", "resolved",
                "failed"]


class Event(BaseModel):
    """A normalized CloudTrail record. `raw` keeps the original for evidence drill-down."""
    id: str
    evidence_id: str | None = None
    time: datetime
    source: str
    name: str
    iam_action: str
    resource: str
    principal: str
    principal_type: str
    access_key: str
    origin_user: str | None = None
    origin_key: str | None = None
    session_issued: datetime | None = None
    ip: str
    user_agent: str
    error: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @property
    def succeeded(self) -> bool:
        return self.error is None


class StreamEvent(BaseModel):
    evidence_id: str
    time: datetime
    name: str
    source: str
    principal: str
    access_key: str
    ip: str
    resource: str
    error: str | None
    detectors: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    id: str
    source: Literal["cloudtrail", "baseline", "deployments", "threat_intel", "semgrep", "iam_state", "sandbox",
                    "memory"]
    timestamp: datetime | None = None
    summary: str
    raw: dict[str, Any] | list[Any]


class Signal(BaseModel):
    detector: str
    title: str
    severity: int
    weight: float
    evidence_ids: list[str]
    timestamp: datetime


class Claim(BaseModel):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: str
    title: str
    confidence: float
    supporting: list[Claim]
    counter: list[Claim]
    reasoning: str
    factors: list[dict[str, Any]] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    start: datetime
    end: datetime
    tactic: str
    technique: str
    actions: list[str]
    evidence_ids: list[str]


class GraphNode(BaseModel):
    id: str
    label: str
    kind: Literal["credential", "user", "role", "policy", "resource"]
    layer: int
    critical: bool = False
    compromised: bool = False
    disabled: bool = False
    detail: str = ""


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    blocked: bool = False


class Graph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class AttackPath(BaseModel):
    credential: str
    nodes: list[str]
    target: str
    target_name: str
    permission: str
    compromised_credential: bool


class BlastRadius(BaseModel):
    graph_before: Graph
    graph_after: Graph | None = None
    paths_before: list[AttackPath]
    paths_after: list[AttackPath] | None = None
    critical_assets_reachable: list[str]
    accessed_during_incident: list[str]
    summary: str = ""


class Action(BaseModel):
    id: str
    kind: str
    title: str
    target: str
    risk: Risk
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    params: dict[str, Any] = Field(default_factory=dict)
    status: ActionStatus = "proposed"
    status_reason: str = ""
    attempt: int = 1
    executed_at: datetime | None = None
    rollback: dict[str, Any] | None = None


class CheckResult(BaseModel):
    id: str
    category: Literal["attack_blocked", "app_healthy", "exposure", "guardrail"]
    name: str
    passed: bool
    detail: str
    environment: Literal["sandbox", "production"]
    attempt: int
    items: list[dict[str, Any]] = Field(default_factory=list)


class AgentStep(BaseModel):
    t: datetime
    agent: str
    kind: Literal["start", "tool", "thought", "result", "handoff", "error", "decision"]
    message: str
    data: dict[str, Any] | None = None


class Incident(BaseModel):
    id: str
    title: str
    severity: Literal["SEV-1", "SEV-2", "SEV-3"]
    status: str
    principal: str
    opened_at: datetime
    resolved_at: datetime | None = None
    confidence: float
    signals: list[Signal] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    narrative: str = ""
    blast_radius: BlastRadius | None = None
    actions: list[Action] = Field(default_factory=list)
    verification: list[CheckResult] = Field(default_factory=list)
    postmortem: str | None = None
    attacker_ips: list[str] = Field(default_factory=list)
    attacker_keys: list[str] = Field(default_factory=list)


class Integrations(BaseModel):
    reasoning: str
    knowledge: str = ""
    event_store: str
    code_scanner: str
    threat_intel: str
    executor: str


class RunState(BaseModel):
    run_id: str
    phase: Phase = "idle"
    started_at: datetime | None = None
    sim_clock: datetime | None = None
    events: list[StreamEvent] = Field(default_factory=list)
    total_events: int = 0
    evidence: dict[str, Evidence] = Field(default_factory=dict)
    incident: Incident | None = None
    agent_log: list[AgentStep] = Field(default_factory=list)
    integrations: Integrations | None = None
    error: str | None = None
