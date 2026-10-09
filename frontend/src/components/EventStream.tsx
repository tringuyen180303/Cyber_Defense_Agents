import { useEffect, useRef } from "react";
import type { RunState } from "../types";
import { Ev, hms, shortArn, shortKey } from "../util";

export function EventStream({ state }: { state: RunState }) {
  const ref = useRef<HTMLDivElement>(null);
  const events = state.events ?? [];
  const attackerIps = new Set(state.incident?.attacker_ips ?? []);
  const flaggedIps = new Set(events.filter((e) => e.detectors.length).map((e) => e.ip));

  useEffect(() => {
    ref.current?.scrollTo({ top: ref.current.scrollHeight, behavior: "smooth" });
  }, [events.length]);

  return (
    <>
      <div className="panel-title">
        CloudTrail stream <span className="muted">{events.length}/{state.total_events ?? 0}</span>
      </div>
      <div className="stream" ref={ref}>
        {events.length === 0 && <div className="muted pad">Waiting for events…</div>}
        {events.map((e) => {
          const hot = attackerIps.has(e.ip) || flaggedIps.has(e.ip);
          return (
            <div key={e.evidence_id} className={`ev-row ${e.detectors.length ? "flagged" : hot ? "attrib" : ""}`}>
              <div className="ev-line">
                <span className="mono muted">{hms(e.time)}</span>
                <span className={`ev-name ${e.error ? "fail" : ""}`}>{e.name}</span>
                <Ev id={e.evidence_id} />
              </div>
              <div className="ev-meta mono">
                {e.principal} · {shortKey(e.access_key)} · {e.ip}
                {e.resource !== "*" && <> · {shortArn(e.resource)}</>}
                {e.error && <span className="fail"> · {e.error}</span>}
              </div>
              {e.detectors.length > 0 && (
                <div className="ev-tags">
                  {e.detectors.map((d) => (
                    <span key={d} className="det">
                      ⚠ {d}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
}
