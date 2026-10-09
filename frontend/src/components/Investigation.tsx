import type { Incident } from "../types";
import { EvList, hms, pct } from "../util";

export function Investigation({ inc }: { inc: Incident }) {
  return (
    <div className="investigation">
      <div className="col">
        <h3>Detector signals</h3>
        <p className="muted small">
          Deterministic detectors scored against a 30-day baseline. Detection confidence = 1 − ∏(1 − wᵢ) over distinct detectors.
        </p>
        {inc.signals.map((s, i) => (
          <div key={i} className="signal">
            <div>
              <span className="mono muted">{hms(s.timestamp)}</span> <b>{s.detector}</b>{" "}
              <span className="muted">w={s.weight}</span>
            </div>
            <div>{s.title}</div>
            <EvList ids={s.evidence_ids} />
          </div>
        ))}
      </div>
      <div className="col wide">
        <h3>Hypotheses</h3>
        {inc.hypotheses.length === 0 && <div className="muted">Investigator gathering evidence…</div>}
        {inc.hypotheses.map((h, i) => (
          <div key={h.id} className={`hyp ${i === 0 ? "lead" : ""}`}>
            <div className="hyp-head">
              <span className="hyp-title">{h.title}</span>
              <span className="hyp-conf">{pct(h.confidence)}</span>
            </div>
            <div className="bar">
              <div style={{ width: pct(h.confidence) }} />
            </div>
            {i === 0 ? (
              <>
                <div className="label">Evidence</div>
                {h.supporting.map((c, j) => (
                  <div key={j} className="claim ok">
                    ✓ {c.text} <EvList ids={c.evidence_ids} />
                  </div>
                ))}
                {h.counter.length > 0 && <div className="label">Counter-evidence</div>}
                {h.counter.map((c, j) => (
                  <div key={j} className="claim warn">
                    • {c.text} <EvList ids={c.evidence_ids} />
                  </div>
                ))}
                <div className="label">Reasoning</div>
                <p>{h.reasoning}</p>
                <details>
                  <summary className="muted small">How the probability is computed</summary>
                  <p className="muted small">Softmax over summed factor weights per hypothesis; factors are computed in code, not by the LLM.</p>
                  {h.factors.map((f, j) => (
                    <div key={j} className="factor">
                      +{f.weight.toFixed(1)} {f.label} <EvList ids={f.evidence_ids} max={3} />
                    </div>
                  ))}
                </details>
              </>
            ) : (
              <>
                {h.counter.map((c, j) => (
                  <div key={j} className="claim warn small">
                    ✗ {c.text} <EvList ids={c.evidence_ids} max={3} />
                  </div>
                ))}
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
