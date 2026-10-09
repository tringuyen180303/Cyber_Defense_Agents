import type { Incident } from "../types";
import { EvList, hms } from "../util";

const TACTIC_COLOR: Record<string, string> = {
  "Initial Access": "#f97316",
  Discovery: "#38bdf8",
  Persistence: "#a855f7",
  "Privilege Escalation": "#ef4444",
  Collection: "#f43f5e",
  "Credential Access": "#eab308",
};

export function Timeline({ inc }: { inc: Incident }) {
  if (!inc.timeline.length) return <div className="muted">Reconstruction agent running…</div>;
  return (
    <div>
      {inc.narrative && <p className="narrative">{inc.narrative}</p>}
      <div className="timeline">
        {inc.timeline.map((t, i) => (
          <div key={i} className="tl-item">
            <div className="tl-time mono">{hms(t.start)}</div>
            <div className="tl-dot" style={{ background: TACTIC_COLOR[t.tactic] ?? "#64748b" }} />
            <div className="tl-body">
              <div className="tl-tactic" style={{ color: TACTIC_COLOR[t.tactic] ?? "#cbd5e1" }}>
                {t.tactic}
              </div>
              <div className="muted small">{t.technique}</div>
              <ul>
                {t.actions.map((a) => (
                  <li key={a} className="mono">
                    {a}
                  </li>
                ))}
              </ul>
              <EvList ids={t.evidence_ids} max={8} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
