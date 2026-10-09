import Markdown from "react-markdown";
import type { Incident } from "../types";
import { Ev } from "../util";

function linkEvidence(md: string) {
  return md.replace(/\[((?:E\d+)(?:,\s*E\d+)*)(…)?\]/g, (_m, ids: string, more?: string) =>
    ids
      .split(/,\s*/)
      .map((id) => `[${id}](#ev-${id})`)
      .join(" ") + (more ? " …" : ""),
  );
}

export function Postmortem({ inc }: { inc: Incident }) {
  if (!inc.postmortem) return <div className="muted">Postmortem is written after production verification.</div>;
  return (
    <div className="postmortem">
      <div className="pm-actions">
        <a href="/api/postmortem.md" target="_blank" rel="noreferrer">
          Download markdown
        </a>
      </div>
      <Markdown
        components={{
          a: ({ href, children }) =>
            href?.startsWith("#ev-") ? <Ev id={href.slice(4)} /> : <a href={href}>{children}</a>,
        }}
      >
        {linkEvidence(inc.postmortem)}
      </Markdown>
    </div>
  );
}
