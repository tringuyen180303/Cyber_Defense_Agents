import type { CheckResult, Incident } from "../types";

const CAT: Record<string, string> = {
  attack_blocked: "Attack replay blocked",
  app_healthy: "Legitimate workloads healthy",
  exposure: "Exposure",
  guardrail: "Guardrails",
};

export function Verification({ inc }: { inc: Incident }) {
  if (!inc.verification.length) return <div className="muted">Verifier waiting for a plan…</div>;
  const groups: { key: string; title: string; checks: CheckResult[] }[] = [];
  for (const c of inc.verification) {
    const key = `${c.environment}-${c.attempt}`;
    let g = groups.find((x) => x.key === key);
    if (!g) {
      g = { key, title: c.environment === "sandbox" ? `Sandbox · plan v${c.attempt}` : "Production", checks: [] };
      groups.push(g);
    }
    g.checks.push(c);
  }
  return (
    <div className="verification">
      {groups.map((g) => {
        const passed = g.checks.filter((c) => c.passed).length;
        const ok = passed === g.checks.length;
        return (
          <div key={g.key} className={`vgroup ${ok ? "pass" : "fail"}`}>
            <div className="vhead">
              <span className={`badge ${ok ? "ok" : "bad"}`}>{ok ? "PASS" : "FAIL"}</span>
              <b>{g.title}</b>
              <span className="muted">
                {passed}/{g.checks.length} checks
              </span>
            </div>
            {Object.keys(CAT).map((cat) => {
              const cs = g.checks.filter((c) => c.category === cat);
              if (!cs.length) return null;
              return (
                <div key={cat} className="vcat">
                  <div className="label">{CAT[cat]}</div>
                  {cs.map((c) => (
                    <details key={c.id} className={`check ${c.passed ? "ok" : "bad"}`}>
                      <summary>
                        <span>{c.passed ? "✓" : "✗"}</span> {c.name} <span className="muted small">— {c.detail}</span>
                      </summary>
                      {c.items.length > 0 && (
                        <table>
                          <tbody>
                            {c.items.map((it, i) => (
                              <tr key={i}>
                                <td className="mono">{it.op}</td>
                                <td>{it.count > 1 ? `×${it.count}` : ""}</td>
                                <td className={it.denied === it.count ? "ok" : "bad"}>
                                  {cat === "exposure" ? "" : it.denied === it.count ? "denied" : "ALLOWED"}
                                </td>
                                <td className="muted small">{it.reason}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      )}
                    </details>
                  ))}
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}
