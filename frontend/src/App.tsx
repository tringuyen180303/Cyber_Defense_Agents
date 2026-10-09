import { useEffect, useMemo, useRef, useState } from "react";
import type { RunState } from "./types";
import { EvidenceCtx } from "./util";
import { EventStream } from "./components/EventStream";
import { AgentFeed } from "./components/AgentFeed";
import { IncidentHeader, Lifecycle } from "./components/IncidentHeader";
import { Investigation } from "./components/Investigation";
import { Timeline } from "./components/Timeline";
import { BlastGraph } from "./components/BlastGraph";
import { Remediation } from "./components/Remediation";
import { Verification } from "./components/Verification";
import { Postmortem } from "./components/Postmortem";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { Learning } from "./components/Learning";

const TABS = ["Investigation", "Attack timeline", "Blast radius", "Remediation", "Verification", "Postmortem"] as const;
type Tab = (typeof TABS)[number];

function followTab(s: RunState): Tab {
  const inc = s.incident;
  if (!inc) return "Investigation";
  if (inc.postmortem) return "Postmortem";
  if (s.phase === "awaiting_approval" || s.phase === "executing") return "Remediation";
  if (inc.verification.length) return "Verification";
  if (inc.actions.length) return "Remediation";
  if (inc.blast_radius) return "Blast radius";
  if (inc.timeline.length) return "Attack timeline";
  return "Investigation";
}

export default function App() {
  const [state, setState] = useState<RunState>({ phase: "idle" });
  const [connected, setConnected] = useState(false);
  const [tab, setTab] = useState<Tab>("Investigation");
  const [follow, setFollow] = useState(true);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [view, setView] = useState<"incident" | "learning">("incident");
  const lastAuto = useRef<Tab>("Investigation");

  useEffect(() => {
    const es = new EventSource("/api/stream");
    es.addEventListener("state", (m) => setState(JSON.parse((m as MessageEvent).data)));
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    return () => es.close();
  }, []);

  useEffect(() => {
    if (!follow) return;
    const t = followTab(state);
    if (t !== lastAuto.current) {
      lastAuto.current = t;
      setTab(t);
    }
  }, [state, follow]);

  const post = (path: string, body?: unknown) =>
    fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

  const simulate = async () => {
    setFollow(true);
    lastAuto.current = "Investigation";
    setTab("Investigation");
    await post("/api/simulate");
  };

  const ctx = useMemo(() => ({ evidence: state.evidence ?? {}, open: setDrawer }), [state.evidence]);
  const inc = state.incident;
  const running = !["idle", "resolved", "failed"].includes(state.phase);

  return (
    <EvidenceCtx.Provider value={ctx}>
      <div className="app">
        <header className="top">
          <div className="brand">
            <span className="logo">◆</span> Sentinel
            <span className="tag">Autonomous Cloud Incident Response</span>
          </div>
          <div className="views">
            <button className={view === "incident" ? "active" : ""} onClick={() => setView("incident")}>
              Incident response
            </button>
            <button className={view === "learning" ? "active" : ""} onClick={() => setView("learning")}>
              Self-improvement
            </button>
          </div>
          <div className="integrations">
            {state.integrations &&
              Object.entries(state.integrations).map(([k, v]) => (
                <span key={k} className="chip" title={`${k.replace("_", " ")}: ${v}`}>
                  <b>{k.replace("_", " ")}</b> {v.split(" (")[0]}
                </span>
              ))}
          </div>
          <div className="controls">
            <span className={`dot ${connected ? "ok" : "bad"}`} title={connected ? "connected" : "disconnected"} />
            <span className={`phase phase-${state.phase}`}>{state.phase.replace("_", " ")}</span>
            <button className="primary" onClick={simulate} disabled={running}>
              {running ? "Running…" : "▶ Simulate credential attack"}
            </button>
            <button onClick={() => post("/api/reset")}>Reset</button>
          </div>
        </header>

        {view === "learning" ? (
          <main className="learn-main">
            <Learning />
          </main>
        ) : (
        <main className="grid">
          <section className="panel left">
            <EventStream state={state} />
          </section>

          <section className="center">
            {!inc ? (
              <div className="panel hero">
                {state.phase === "idle" ? (
                  <>
                    <h1>From CloudTrail alert to verified remediation.</h1>
                    <p>
                      Sentinel watches a sandbox AWS account (CI pipeline → IAM role → S3, ECR, Secrets Manager), detects
                      credential misuse with deterministic detectors, and dispatches a team of agents to investigate,
                      reconstruct, scope, contain, and verify — every claim linked to evidence.
                    </p>
                    <button className="primary big" onClick={simulate}>
                      ▶ Simulate credential attack
                    </button>
                  </>
                ) : (
                  <>
                    <h2>Monitoring…</h2>
                    <p className="muted">
                      {state.events?.length ?? 0}/{state.total_events ?? 0} events analyzed against the behavioral baseline.
                    </p>
                  </>
                )}
                {state.error && <p className="fail">{state.error}</p>}
              </div>
            ) : (
              <>
                <IncidentHeader state={state} />
                <Lifecycle state={state} />
                <div className="tabs">
                  {TABS.map((t) => (
                    <button
                      key={t}
                      className={t === tab ? "active" : ""}
                      onClick={() => {
                        setTab(t);
                        setFollow(false);
                      }}
                    >
                      {t}
                    </button>
                  ))}
                  <label className="follow">
                    <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} /> follow agents
                  </label>
                </div>
                <div className="panel tabbody">
                  {tab === "Investigation" && <Investigation inc={inc} />}
                  {tab === "Attack timeline" && <Timeline inc={inc} />}
                  {tab === "Blast radius" && <BlastGraph inc={inc} />}
                  {tab === "Remediation" && <Remediation inc={inc} phase={state.phase} post={post} />}
                  {tab === "Verification" && <Verification inc={inc} />}
                  {tab === "Postmortem" && <Postmortem inc={inc} />}
                </div>
              </>
            )}
          </section>

          <section className="panel right">
            <AgentFeed steps={state.agent_log ?? []} />
          </section>
        </main>
        )}
        {drawer && <EvidenceDrawer id={drawer} onClose={() => setDrawer(null)} />}
      </div>
    </EvidenceCtx.Provider>
  );
}
