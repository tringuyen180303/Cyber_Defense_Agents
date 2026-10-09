import { useMemo, useState } from "react";
import { Background, Controls, MarkerType, ReactFlow, type Edge, type Node } from "@xyflow/react";
import type { AttackPath, Graph, Incident } from "../types";
import { shortKey } from "../util";

const LAYER_X = [0, 230, 450, 670, 890, 1110];
const KIND_ICON: Record<string, string> = { credential: "🔑", user: "👤", role: "🎭", policy: "📜", resource: "🗄" };

function layout(graph: Graph, paths: AttackPath[]): { nodes: Node[]; edges: Edge[] } {
  const hot = new Set<string>();
  for (const p of paths.filter((p) => p.compromised_credential)) {
    for (let i = 0; i < p.nodes.length - 1; i++) hot.add(`${p.nodes[i]}|${p.nodes[i + 1]}`);
  }
  const byLayer: Record<number, number> = {};
  const order = [...graph.nodes].sort((a, b) => a.layer - b.layer || Number(b.critical) - Number(a.critical) || a.id.localeCompare(b.id));
  const nodes: Node[] = order.map((n) => {
    const idx = (byLayer[n.layer] = (byLayer[n.layer] ?? -1) + 1);
    const cls = [
      "gnode",
      `k-${n.kind}`,
      n.critical ? "critical" : "",
      n.compromised ? "compromised" : "",
      n.disabled ? "disabled" : "",
    ].join(" ");
    return {
      id: n.id,
      position: { x: LAYER_X[n.layer] ?? n.layer * 220, y: idx * 86 },
      data: {
        label: (
          <div title={n.detail}>
            <div className="gl">
              {KIND_ICON[n.kind]} {n.kind === "credential" ? n.label.replace(/(AKIA|ASIA)\w+/, (m) => shortKey(m)) : n.label}
            </div>
            <div className="gs">
              {n.disabled ? "disabled" : n.compromised ? "compromised" : n.critical ? "critical" : n.detail}
            </div>
          </div>
        ),
      },
      className: cls,
      sourcePosition: "right" as never,
      targetPosition: "left" as never,
    };
  });
  const edges: Edge[] = graph.edges.map((e) => {
    const isHot = !e.blocked && hot.has(`${e.source}|${e.target}`);
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.blocked ? "✕ " + e.label : e.label,
      animated: isHot,
      style: {
        stroke: e.blocked ? "#475569" : isHot ? "#ef4444" : "#64748b",
        strokeWidth: isHot ? 2.4 : 1.2,
        strokeDasharray: e.blocked ? "5 5" : undefined,
      },
      labelStyle: { fill: e.blocked ? "#64748b" : isHot ? "#fca5a5" : "#94a3b8", fontSize: 10 },
      labelBgStyle: { fill: "#0b1220" },
      markerEnd: { type: MarkerType.ArrowClosed, color: e.blocked ? "#475569" : isHot ? "#ef4444" : "#64748b" },
    };
  });
  return { nodes, edges };
}

export function BlastGraph({ inc }: { inc: Incident }) {
  const br = inc.blast_radius;
  const hasAfter = !!br?.graph_after;
  const [view, setView] = useState<"before" | "after">("before");
  const showAfter = view === "after" && hasAfter;
  const { nodes, edges } = useMemo(() => {
    if (!br) return { nodes: [], edges: [] };
    return showAfter ? layout(br.graph_after!, br.paths_after ?? []) : layout(br.graph_before, br.paths_before);
  }, [br, showAfter]);

  if (!br) return <div className="muted">Blast-radius agent building access graph…</div>;
  const before = br.paths_before;
  const after = br.paths_after;
  const compBefore = before.filter((p) => p.compromised_credential).length;
  const compAfter = after?.filter((p) => p.compromised_credential).length;
  const reduction = after ? Math.round((1 - after.length / Math.max(before.length, 1)) * 100) : null;

  return (
    <div className="blast">
      <div className="blast-head">
        <div className="toggle">
          <button className={!showAfter ? "active" : ""} onClick={() => setView("before")}>
            Before
          </button>
          <button className={showAfter ? "active" : ""} onClick={() => setView("after")} disabled={!hasAfter}>
            After remediation
          </button>
        </div>
        <div className="kpis">
          <span>
            Attack paths <b className="bad">{before.length}</b>
            {after && (
              <>
                {" "}→ <b className="ok">{after.length}</b>
              </>
            )}
          </span>
          <span>
            via compromised creds <b className="bad">{compBefore}</b>
            {compAfter !== undefined && (
              <>
                {" "}→ <b className="ok">{compAfter}</b>
              </>
            )}
          </span>
          {reduction !== null && (
            <span>
              Risk reduction <b className="ok">{reduction}%</b>
            </span>
          )}
        </div>
      </div>
      <p className="muted small">{br.summary}</p>
      <div className="flow">
        <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} nodesDraggable minZoom={0.3}>
          <Background color="#1e293b" gap={24} />
          <Controls showInteractive={false} />
        </ReactFlow>
      </div>
      <div className="paths">
        <h4>{showAfter ? "Remaining paths" : "Attack paths to critical assets"}</h4>
        {(showAfter ? after ?? [] : before).map((p, i) => (
          <div key={i} className={`path ${p.compromised_credential ? "bad" : "muted"}`}>
            <span className="mono">{shortKey(p.credential)}</span> →{" "}
            {p.nodes
              .slice(1, -1)
              .map((n) => n.split(":").slice(-1)[0])
              .join(" → ")}{" "}
            → <b>{p.target_name}</b> <span className="muted">({p.permission})</span>
            {!p.compromised_credential && <span className="muted"> · residual, non-compromised credential</span>}
          </div>
        ))}
        {showAfter && after?.length === 0 && <div className="ok">No paths remain.</div>}
      </div>
    </div>
  );
}
