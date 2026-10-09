import { useEffect, useRef } from "react";
import type { AgentStep } from "../types";
import { EvList, hms } from "../util";

const ICON: Record<string, string> = {
  start: "▸",
  tool: "⚙",
  thought: "…",
  result: "✓",
  handoff: "⇢",
  error: "!",
  decision: "◆",
};

const COLOR: Record<string, string> = {
  Detection: "#f59e0b",
  "Incident Commander": "#a78bfa",
  Investigator: "#38bdf8",
  Reconstruction: "#f472b6",
  "Blast Radius": "#fb7185",
  "Remediation Planner": "#34d399",
  Verifier: "#facc15",
  Executor: "#22d3ee",
  Postmortem: "#94a3b8",
  Human: "#ffffff",
};

export function AgentFeed({ steps }: { steps: AgentStep[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [steps.length]);
  return (
    <>
      <div className="panel-title">
        Agent activity <span className="muted">{steps.length}</span>
      </div>
      <div className="feed" ref={ref}>
        {steps.map((s, i) => {
          const ids = (s.data?.evidence_ids as string[]) ?? (s.data?.evidence_id ? [s.data.evidence_id as string] : []);
          return (
            <div key={i} className={`step step-${s.kind}`}>
              <span className="mono muted">{hms(s.t)}</span>
              <span className="agent" style={{ color: COLOR[s.agent] ?? "#ccc" }}>
                {ICON[s.kind] ?? "·"} {s.agent}
              </span>
              <div className="msg">
                {s.message} <EvList ids={ids} max={4} />
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}
