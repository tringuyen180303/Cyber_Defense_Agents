import { useEffect, useRef, useState } from "react";
import Markdown from "react-markdown";
import { pct } from "../util";

interface Metrics {
  recall: number;
  false_positives: number;
  avg_attempts: number;
  first_try_rate: number;
  avg_time_to_detect: number;
  contained_rate: number;
  prod_pass_rate: number;
  scenarios: number;
  attacks: number;
  benign: number;
}
interface Cell {
  detected: boolean;
  correct: boolean;
  confidence: number;
  plan_attempts: number | null;
}
interface LearningData {
  current: number;
  versions: { version: number; summary: string; detectors: number; learned_detectors: number; playbooks: number; created: string }[];
  pending: null | {
    summary: string;
    trigger: string;
    parent: number;
    changes: { type: string; description: string; trigger: string }[];
    base_metrics: Metrics;
    metrics: Metrics;
    tested: { description: string; verdict: string; trigger: string }[];
  };
  running: string | null;
  log: { t: string; msg: string }[];
  changelog: string;
  memories: number;
  knowledge_yaml: string;
  grafana_url?: string | null;
  matrix: null | {
    scenarios: { id: string; label: string; source: string; description: string }[];
    versions: Record<string, { metrics: Metrics; results: Record<string, Cell> }>;
  };
}

const post = (path: string, body?: unknown) =>
  fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });

export function Learning() {
  const [d, setD] = useState<LearningData | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await fetch("/api/learning");
        if (alive && r.ok) setD(await r.json());
      } catch {
        /* backend restarting */
      }
    };
    tick();
    const id = setInterval(tick, 1200);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [d?.log.length]);

  if (!d) return <div className="panel pad muted">Loading knowledge store…</div>;
  const versions = Object.keys(d.matrix?.versions ?? {}).map(Number).sort((a, b) => a - b);
  const first = d.matrix?.versions[String(versions[0])]?.metrics;
  const cur = d.matrix?.versions[String(d.current)]?.metrics;
  const busy = !!d.running;

  return (
    <div className="learning">
      <div className="panel learn-head">
        <div>
          <h2>Self-improvement loop</h2>
          <p className="muted small">
            Red Team hunts for evasions → Learner proposes knowledge changes → Evaluator replays every scenario and rejects any
            regression → a human approves promotion. Guardrails, risk tiers and the evaluator are code and are never learned.
          </p>
        </div>
        <div className="learn-btns">
          <button className="primary" disabled={busy} onClick={() => post("/api/learning/redteam")}>
            ⚔ Run red-team round
          </button>
          <button disabled={busy} onClick={() => post("/api/learning/learn")}>
            🧠 Learn from current suite
          </button>
          <button disabled={busy} onClick={() => post("/api/learning/reset")}>
            Reset to v1
          </button>
          {d.grafana_url && (
            <a className="trace-link" href={d.grafana_url} target="_blank" rel="noreferrer">
              Grafana ↗
            </a>
          )}
          {busy && <span className="phase phase-verifying">{d.running} running…</span>}
        </div>
      </div>

      <div className="learn-kpis">
        <Kpi label="Knowledge version" value={`v${d.current}`} sub={`${versions.length} versions`} />
        <Kpi label="Recall (attacks caught)" value={cur ? pct(cur.recall) : "…"} from={first ? pct(first.recall) : undefined} />
        <Kpi label="False positives" value={cur ? String(cur.false_positives) : "…"} from={first ? String(first.false_positives) : undefined} />
        <Kpi label="Plans passing sandbox first try" value={cur ? pct(cur.first_try_rate) : "…"} from={first ? pct(first.first_try_rate) : undefined} />
        <Kpi label="Events to detect" value={cur ? cur.avg_time_to_detect.toFixed(1) : "…"} from={first ? first.avg_time_to_detect.toFixed(1) : undefined} />
        <Kpi label="Scenarios in suite" value={cur ? String(cur.scenarios) : "…"} sub={`${d.matrix?.scenarios.filter((s) => s.source === "red-team").length ?? 0} found by red team`} />
        <Kpi label="Episodic memory" value={String(d.memories)} sub="past incidents" />
      </div>

      <div className="learn-grid">
        <div className="panel pad">
          {d.pending ? (
            <div className="pending">
              <div className="label">Candidate awaiting approval · from v{d.pending.parent} · trigger: {d.pending.trigger}</div>
              <h3 className="cand-title">{d.pending.summary}</h3>
              {d.pending.changes.map((c, i) => (
                <div key={i} className="claim ok">
                  + {c.description} <span className="muted small">— {c.trigger}</span>
                </div>
              ))}
              <MetricDiff a={d.pending.base_metrics} b={d.pending.metrics} />
              <details>
                <summary className="small muted">
                  Evaluator tested {d.pending.tested.length} candidate changes ({d.pending.tested.filter((t) => t.verdict.startsWith("rejected")).length} rejected
                  for regressions)
                </summary>
                {d.pending.tested.map((t, i) => (
                  <div key={i} className={`small ${t.verdict.startsWith("rejected") ? "bad" : t.verdict === "improves" ? "ok" : "muted"}`}>
                    {t.verdict.startsWith("rejected") ? "✗" : t.verdict === "improves" ? "✓" : "·"} {t.description} — {t.verdict}
                  </div>
                ))}
              </details>
              <div className="action-btns">
                <button className="primary" onClick={() => post("/api/learning/approve")}>
                  Approve & promote to v{Math.max(...d.versions.map((v) => v.version)) + 1}
                </button>
                <button onClick={() => post("/api/learning/reject")}>Reject</button>
              </div>
            </div>
          ) : (
            <div className="muted">No pending candidate. Run a red-team round or learn from the current suite.</div>
          )}
          <div className="label">Learning log</div>
          <div className="learn-log mono" ref={logRef}>
            {d.log.map((l, i) => (
              <div key={i} className={l.msg.includes("✗") || l.msg.includes("rejected") ? "muted" : l.msg.startsWith("evasion") ? "bad" : l.msg.includes("accepted") || l.msg.includes("promoted") ? "ok" : ""}>
                {l.msg}
              </div>
            ))}
          </div>
        </div>

        <div className="panel pad">
          <div className="label">Trend across versions (evaluated on today's suite)</div>
          {d.matrix && <Trend versions={versions} data={d.matrix.versions} />}
          <div className="label">Scenario × version</div>
          {d.matrix && (
            <div className="matrix-wrap">
              <table className="matrix">
                <thead>
                  <tr>
                    <th>scenario</th>
                    {versions.map((v) => (
                      <th key={v} className={v === d.current ? "cur" : ""}>
                        v{v}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {d.matrix.scenarios.map((s) => (
                    <tr key={s.id} title={s.description}>
                      <td className="mono">
                        {s.source === "red-team" ? "⚔ " : ""}
                        {s.id}
                        <span className={`lbl lbl-${s.label}`}>{s.label}</span>
                      </td>
                      {versions.map((v) => {
                        const c = d.matrix!.versions[String(v)].results[s.id];
                        if (!c) return <td key={v}>–</td>;
                        const txt = s.label === "attack" ? (c.detected ? (c.plan_attempts === 1 ? "✓" : `✓${c.plan_attempts}`) : "miss") : c.detected ? "FP" : "✓";
                        return (
                          <td key={v} className={c.correct ? "ok" : "bad"} title={`confidence ${c.confidence}`}>
                            {txt}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="muted small">✓2 = caught but plan needed 2 sandbox attempts · ⚔ = discovered by red team</div>
            </div>
          )}
        </div>
      </div>

      <div className="learn-grid">
        <div className="panel pad changelog">
          <div className="label">Changelog</div>
          {d.changelog ? <Markdown>{d.changelog}</Markdown> : <div className="muted">No promotions yet.</div>}
        </div>
        <div className="panel pad">
          <div className="label">Current knowledge (knowledge/versions/v{d.current}.yaml)</div>
          <pre className="yaml">{d.knowledge_yaml}</pre>
          <div className="label">Versions</div>
          {d.versions.map((v) => (
            <div key={v.version} className="small ver">
              <b>v{v.version}</b> {v.version === d.current && <span className="ok">current</span>} — {v.detectors} detectors ({v.learned_detectors}{" "}
              learned), {v.playbooks} playbooks · <span className="muted">{v.summary}</span>
              {v.version !== d.current && (
                <button className="tiny" disabled={busy} onClick={() => post("/api/learning/rollback", { version: v.version })}>
                  rollback
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, from, sub }: { label: string; value: string; from?: string; sub?: string }) {
  return (
    <div className="panel kpi">
      <div className="stat-label">{label}</div>
      <div className="stat-value">
        {from !== undefined && from !== value && <span className="muted from">{from} → </span>}
        {value}
      </div>
      {sub && <div className="muted small">{sub}</div>}
    </div>
  );
}

function MetricDiff({ a, b }: { a: Metrics; b: Metrics }) {
  const rows: [string, (m: Metrics) => string, (x: Metrics, y: Metrics) => boolean][] = [
    ["Recall", (m) => pct(m.recall), (x, y) => y.recall > x.recall],
    ["False positives", (m) => String(m.false_positives), (x, y) => y.false_positives < x.false_positives],
    ["First-try plans", (m) => pct(m.first_try_rate), (x, y) => y.first_try_rate > x.first_try_rate],
    ["Events to detect", (m) => m.avg_time_to_detect.toFixed(2), (x, y) => y.avg_time_to_detect < x.avg_time_to_detect],
    ["Contained", (m) => pct(m.contained_rate), (x, y) => y.contained_rate > x.contained_rate],
    ["Prod checks pass", (m) => pct(m.prod_pass_rate), (x, y) => y.prod_pass_rate > x.prod_pass_rate],
  ];
  return (
    <table className="mdiff">
      <tbody>
        {rows.map(([n, f, better]) => (
          <tr key={n}>
            <td className="muted">{n}</td>
            <td>{f(a)}</td>
            <td>→</td>
            <td className={better(a, b) ? "ok" : f(a) === f(b) ? "" : "bad"}>{f(b)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Trend({ versions, data }: { versions: number[]; data: Record<string, { metrics: Metrics }> }) {
  const W = 460,
    H = 140,
    P = 24;
  const x = (i: number) => P + (versions.length === 1 ? 0 : (i * (W - 2 * P)) / (versions.length - 1));
  const y = (v: number) => H - P - v * (H - 2 * P - 8);
  const series: [string, string, (m: Metrics) => number][] = [
    ["recall", "#22c55e", (m) => m.recall],
    ["first-try plans", "#38bdf8", (m) => m.first_try_rate],
    ["benign quiet", "#a78bfa", (m) => (m.benign ? 1 - m.false_positives / m.benign : 1)],
  ];
  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} className="trend">
      {[0, 0.5, 1].map((g) => (
        <g key={g}>
          <line x1={P} x2={W - P} y1={y(g)} y2={y(g)} stroke="#1e293b" />
          <text x={2} y={y(g) + 3} fill="#64748b" fontSize="9">
            {g * 100}%
          </text>
        </g>
      ))}
      {versions.map((v, i) => (
        <text key={v} x={x(i)} y={H - 6} fill="#64748b" fontSize="10" textAnchor="middle">
          v{v}
        </text>
      ))}
      {series.map(([name, color, f], si) => (
        <g key={name}>
          <polyline fill="none" stroke={color} strokeWidth="2" points={versions.map((v, i) => `${x(i)},${y(f(data[String(v)].metrics))}`).join(" ")} />
          {versions.map((v, i) => (
            <circle key={v} cx={x(i)} cy={y(f(data[String(v)].metrics))} r="3" fill={color} />
          ))}
          <text x={P + 4 + si * 110} y={11} fill={color} fontSize="10">
            ● {name}
          </text>
        </g>
      ))}
    </svg>
  );
}
