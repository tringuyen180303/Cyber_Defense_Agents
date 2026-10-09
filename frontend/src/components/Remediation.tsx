import type { Action, Incident, Risk } from "../types";
import { EvList, hms } from "../util";

const TIERS: { risk: Risk; label: string; note: string }[] = [
  { risk: "safe", label: "SAFE", note: "Reversible, no production impact — auto-executed after sandbox pass" },
  { risk: "review", label: "REVIEW", note: "Sandbox-verified — requires human approval" },
  { risk: "dangerous", label: "DANGEROUS", note: "Irreversible — never executed by Sentinel" },
];

const STATUS_LABEL: Record<string, string> = {
  proposed: "proposed",
  sandbox_pass: "sandbox ✓",
  sandbox_fail: "sandbox ✗",
  awaiting_approval: "awaiting approval",
  approved: "approved",
  executed: "executed",
  blocked: "blocked",
  superseded: "superseded",
};

export function Remediation({
  inc,
  phase,
  post,
}: {
  inc: Incident;
  phase: string;
  post: (p: string, b?: unknown) => Promise<Response>;
}) {
  if (!inc.actions.length) return <div className="muted">Remediation planner waiting for investigation…</div>;
  const live = inc.actions.filter((a) => a.status !== "superseded");
  const history = inc.actions.filter((a) => a.status === "superseded");
  const pending = live.filter((a) => a.status === "awaiting_approval");
  return (
    <div className="remediation">
      {phase === "awaiting_approval" && pending.length > 0 && (
        <div className="approval">
          <div>
            <b>{pending.length} REVIEW action(s)</b> passed sandbox verification and are waiting for approval.
          </div>
          <button className="primary" onClick={() => post("/api/decision", { approve: null })}>
            Approve all & execute
          </button>
        </div>
      )}
      {TIERS.map((t) => {
        const acts = live.filter((a) => a.risk === t.risk);
        if (!acts.length) return null;
        return (
          <div key={t.risk} className={`tier tier-${t.risk}`}>
            <div className="tier-head">
              <span className={`risk risk-${t.risk}`}>{t.label}</span> <span className="muted small">{t.note}</span>
            </div>
            {acts.map((a) => (
              <ActionCard key={a.id + a.attempt} a={a} post={post} />
            ))}
          </div>
        );
      })}
      {history.length > 0 && (
        <div className="tier history">
          <div className="tier-head">
            <span className="risk">PLAN HISTORY</span> <span className="muted small">replaced after sandbox verification failed</span>
          </div>
          {history.map((a) => (
            <ActionCard key={a.id + "h"} a={a} post={post} />
          ))}
        </div>
      )}
    </div>
  );
}

function ActionCard({ a, post }: { a: Action; post: (p: string, b?: unknown) => Promise<Response> }) {
  const policy = a.params.new_policy as Record<string, unknown> | undefined;
  const rollback = a.rollback ? Object.fromEntries(Object.entries(a.rollback).filter(([k]) => k !== "previous_policy")) : null;
  return (
    <div className={`action st-${a.status}`}>
      <div className="action-head">
        <span className="mono muted">{a.id}</span>
        <span className="action-title">{a.title}</span>
        <span className={`status s-${a.status}`}>{STATUS_LABEL[a.status] ?? a.status}</span>
      </div>
      <div className="small">
        {a.rationale} <EvList ids={a.evidence_ids} max={4} />
      </div>
      {a.status_reason && <div className="small muted">{a.status_reason}</div>}
      {a.executed_at && <div className="small muted">executed {hms(a.executed_at)} UTC</div>}
      {(policy || rollback) && (
        <details>
          <summary className="small muted">details</summary>
          {policy && (
            <>
              <div className="label">Generated least-privilege policy (from 30-day observed usage)</div>
              <pre>{JSON.stringify(policy, null, 2)}</pre>
            </>
          )}
          {rollback && Object.keys(rollback).length > 0 && (
            <>
              <div className="label">Rollback record</div>
              <pre>{JSON.stringify(rollback, null, 2)}</pre>
            </>
          )}
        </details>
      )}
      {a.status === "awaiting_approval" && (
        <div className="action-btns">
          <button className="primary" onClick={() => post("/api/decision", { approve: [a.id] })}>
            Approve
          </button>
          <button onClick={() => post("/api/decision", { approve: [], reject: [a.id] })}>Reject</button>
        </div>
      )}
    </div>
  );
}
