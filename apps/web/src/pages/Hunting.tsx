import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge } from "../components/ui";

const SUGGESTIONS = [
  "Suspicious authentication patterns",
  "New outbound destinations",
  "Unusual process activity",
  "Unexpected privilege changes",
  "Rare network communication",
  "Sensitive data access",
];

export default function Hunting() {
  const [query, setQuery] = useState("");
  const hunt = useMutation({
    mutationFn: (q: string) => api.post<any>("/api/hunts", { query: q }),
  });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Threat Hunting</h1>
        <p className="text-sm text-slate-500">Natural-language requests are translated into validated query plans — never free-form database access</p>
      </div>

      <Card title="Hunt">
        <div className="flex gap-2">
          <input className="input" placeholder="e.g. suspicious authentication patterns" value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === "Enter" && query && hunt.mutate(query)} />
          <button className="btn-primary" disabled={!query || hunt.isPending} onClick={() => hunt.mutate(query)}>
            Run hunt
          </button>
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          {SUGGESTIONS.map((s) => (
            <button key={s} className="rounded-full border border-ink-700 px-2 py-0.5 text-[11px] text-slate-400 hover:border-accent/50 hover:text-accent" onClick={() => { setQuery(s); hunt.mutate(s); }}>
              {s}
            </button>
          ))}
        </div>
      </Card>

      {hunt.data && (
        <Card title="Hunt results">
          {hunt.data.ok ? (
            <>
              <div className="mb-2 flex items-center gap-2">
                <Badge tone="blue">PLAN: {hunt.data.template}</Badge>
                <Badge tone="green">{hunt.data.total_matches} matches</Badge>
                <span className="mono text-[10px] text-slate-500">{hunt.data.plan.note}</span>
              </div>
              <div className="max-h-[480px] space-y-1 overflow-y-auto">
                {hunt.data.results.map((e: any) => (
                  <div key={e.event_id} className="flex items-start gap-2 rounded px-2 py-1 text-xs hover:bg-ink-800">
                    <span className="mono w-32 shrink-0 text-slate-500">{new Date(e.timestamp).toLocaleString()}</span>
                    <SeverityBadge severity={e.severity} />
                    <div className="min-w-0">
                      <span className="mono text-slate-300">{e.event_type}</span>
                      <span className="ml-2 text-[10px] text-slate-500">{e.source}</span>
                      <div className="mono text-[10px] text-slate-600">{JSON.stringify(e.metadata).slice(0, 150)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="rounded border border-amber/40 bg-amber/5 px-3 py-2 text-sm text-amber">{hunt.data.reason}</div>
          )}
        </Card>
      )}

      {!hunt.data && <Empty message="Run a hunt to search telemetry. All hunts use approved query templates." />}
    </div>
  );
}
