import { createContext, useContext } from "react";
import type { Evidence } from "./types";

export const EvidenceCtx = createContext<{
  evidence: Record<string, Evidence>;
  open: (id: string) => void;
}>({ evidence: {}, open: () => {} });

export function hms(t?: string | null) {
  if (!t) return "";
  return new Date(t).toISOString().slice(11, 19);
}

export function shortArn(arn: string) {
  if (!arn || arn === "*") return arn;
  if (arn.startsWith("arn:aws:s3:::")) return "s3://" + arn.slice(13);
  if (arn.includes(":secret:")) return "secret:" + arn.split(":secret:")[1].replace(/-[A-Za-z0-9]{6}$/, "");
  const tail = arn.split(":").slice(5).join(":");
  return tail || arn;
}

export function shortKey(k: string) {
  return k && k.length > 10 ? `${k.slice(0, 4)}…${k.slice(-4)}` : k;
}

export function Ev({ id }: { id: string }) {
  const { evidence, open } = useContext(EvidenceCtx);
  const e = evidence[id];
  return (
    <button className={`ev ev-${e?.source ?? "missing"}`} title={e?.summary ?? "unknown evidence"} onClick={() => open(id)}>
      {id}
    </button>
  );
}

export function EvList({ ids, max = 6 }: { ids: string[]; max?: number }) {
  if (!ids?.length) return null;
  const shown = ids.slice(0, max);
  return (
    <span className="evlist">
      {shown.map((i) => (
        <Ev key={i} id={i} />
      ))}
      {ids.length > max && <span className="muted">+{ids.length - max}</span>}
    </span>
  );
}

export const pct = (x: number) => `${Math.round(x * 100)}%`;
