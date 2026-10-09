import { useContext, useEffect } from "react";
import { EvidenceCtx, hms } from "../util";

export function EvidenceDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const { evidence } = useContext(EvidenceCtx);
  const e = evidence[id];
  useEffect(() => {
    const h = (k: KeyboardEvent) => k.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
  return (
    <div className="drawer-bg" onClick={onClose}>
      <aside className="drawer" onClick={(ev) => ev.stopPropagation()}>
        <div className="drawer-head">
          <span className={`ev ev-${e?.source}`}>{id}</span>
          <span className="muted">{e?.source}</span>
          {e?.timestamp && <span className="mono muted">{hms(e.timestamp)} UTC</span>}
          <button onClick={onClose}>✕</button>
        </div>
        {e ? (
          <>
            <p>{e.summary}</p>
            <div className="label">Raw record</div>
            <pre className="raw">{JSON.stringify(e.raw, null, 2)}</pre>
          </>
        ) : (
          <p className="fail">Evidence {id} not found.</p>
        )}
      </aside>
    </div>
  );
}
