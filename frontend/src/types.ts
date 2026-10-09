export type Risk = "safe" | "review" | "dangerous";

export interface StreamEvent {
  evidence_id: string;
  time: string;
  name: string;
  source: string;
  principal: string;
  access_key: string;
  ip: string;
  resource: string;
  error: string | null;
  detectors: string[];
}

export interface Evidence {
  id: string;
  source: string;
  timestamp: string | null;
  summary: string;
  raw: unknown;
}

export interface Signal {
  detector: string;
  title: string;
  severity: number;
  weight: number;
  evidence_ids: string[];
  timestamp: string;
}

export interface Claim {
  text: string;
  evidence_ids: string[];
}

export interface Hypothesis {
  id: string;
  title: string;
  confidence: number;
  supporting: Claim[];
  counter: Claim[];
  reasoning: string;
  factors: { label: string; weight: number; evidence_ids: string[] }[];
}

export interface TimelineEntry {
  start: string;
  end: string;
  tactic: string;
  technique: string;
  actions: string[];
  evidence_ids: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  kind: "credential" | "user" | "role" | "policy" | "resource";
  layer: number;
  critical: boolean;
  compromised: boolean;
  disabled: boolean;
  detail: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  blocked: boolean;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AttackPath {
  credential: string;
  nodes: string[];
  target: string;
  target_name: string;
  permission: string;
  compromised_credential: boolean;
}

export interface BlastRadius {
  graph_before: Graph;
  graph_after: Graph | null;
  paths_before: AttackPath[];
  paths_after: AttackPath[] | null;
  critical_assets_reachable: string[];
  accessed_during_incident: string[];
  summary: string;
}

export interface Action {
  id: string;
  kind: string;
  title: string;
  target: string;
  risk: Risk;
  rationale: string;
  evidence_ids: string[];
  params: Record<string, unknown>;
  status: string;
  status_reason: string;
  attempt: number;
  executed_at: string | null;
  rollback: Record<string, unknown> | null;
}

export interface CheckResult {
  id: string;
  category: "attack_blocked" | "app_healthy" | "exposure" | "guardrail";
  name: string;
  passed: boolean;
  detail: string;
  environment: "sandbox" | "production";
  attempt: number;
  items: { op: string; count: number; denied: number; reason: string }[];
}

export interface AgentStep {
  t: string;
  agent: string;
  kind: string;
  message: string;
  data: Record<string, unknown> | null;
}

export interface Incident {
  id: string;
  title: string;
  severity: string;
  status: string;
  principal: string;
  opened_at: string;
  resolved_at: string | null;
  confidence: number;
  signals: Signal[];
  hypotheses: Hypothesis[];
  timeline: TimelineEntry[];
  narrative: string;
  blast_radius: BlastRadius | null;
  actions: Action[];
  verification: CheckResult[];
  postmortem: string | null;
  attacker_ips: string[];
  attacker_keys: string[];
}

export interface RunState {
  run_id?: string;
  phase: string;
  started_at?: string | null;
  sim_clock?: string | null;
  events?: StreamEvent[];
  total_events?: number;
  evidence?: Record<string, Evidence>;
  incident?: Incident | null;
  agent_log?: AgentStep[];
  integrations?: Record<string, string> | null;
  error?: string | null;
}
