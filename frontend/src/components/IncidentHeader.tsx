import type { RunState } from "../types";
import { hms, pct } from "../util";

export function IncidentHeader({ state }: { state: RunState }) {
  const inc = state.incident!;
  const br = inc.blast_radius;
  const top = inc.hypotheses[0];
  const before = br?.paths_before.length;
  const after = br?.paths_after?.length;
  const prod = inc.verification.filter((c) => c.environment === "production");
  const resolved = inc.status === "resolved";
  return (
    <div className={`panel incident ${resolved ? "resolved" : ""}`}>
      <div className="inc-top">
        <span className={`sev sev-${inc.severity}`}>{resolved ? "✓ CONTAINED" : `🚨 ${inc.severity}`}</span>
        <h2>{inc.title}</h2>
        <span className="muted mono">
          {inc.id} · opened {hms(inc.opened_at)} UTC
        </span>
      </div>
      <div className="stats">
        <Stat label="Detection confidence" value={pct(inc.confidence)} />
        <Stat label="Root-cause probability" value={top ? pct(top.confidence) : "…"} />
        <Stat label="Affected principal" value={inc.principal} mono />
        <Stat label="Compromised credentials" value={String(inc.attacker_keys.length || "…")} />
        <Stat label="Critical assets reachable" value={br ? String(br.critical_assets_reachable.length) : "…"} />
        <Stat
          label="Attack paths"
          value={before === undefined ? "…" : after === undefined ? String(before) : `${before} → ${after}`}
          accent={after !== undefined ? "ok" : before ? "bad" : undefined}
        />
        <Stat
          label="Production checks"
          value={prod.length ? `${prod.filter((c) => c.passed).length}/${prod.length}` : "…"}
          accent={prod.length ? (prod.every((c) => c.passed) ? "ok" : "bad") : undefined}
        />
      </div>
    </div>
  );
}

function Stat({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: "ok" | "bad" }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className={`stat-value ${mono ? "mono" : ""} ${accent ?? ""}`}>{value}</div>
    </div>
  );
}

const STAGES = ["Detect", "Investigate", "Reconstruct", "Scope", "Plan", "Simulate", "Remediate", "Verify", "Learn"];

export function Lifecycle({ state }: { state: RunState }) {
  const inc = state.incident!;
  const done = [
    true,
    inc.hypotheses.length > 0,
    inc.timeline.length > 0,
    !!inc.blast_radius,
    inc.actions.length > 0,
    inc.verification.some((c) => c.environment === "sandbox"),
    inc.actions.some((a) => a.status === "executed"),
    inc.verification.some((c) => c.environment === "production"),
    !!inc.postmortem,
  ];
  const current = done.indexOf(false);
  return (
    <div className="lifecycle">
      {STAGES.map((s, i) => (
        <div key={s} className={`stage ${done[i] ? "done" : i === current ? "current" : ""}`}>
          <span className="num">{done[i] ? "✓" : i + 1}</span> {s}
        </div>
      ))}
    </div>
  );
}
