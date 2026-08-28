import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner } from "../components/ui";

export default function SOC() {
  const events = useQuery({ queryKey: ["events"], queryFn: () => api.get<any[]>("/api/events?size=100"), refetchInterval: 5000 });
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get<any[]>("/api/detections/rules") });

  const counts = (events.data || []).reduce((acc: Record<string, number>, e: any) => {
    acc[e.severity] = (acc[e.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">SOC Overview</h1>
        <p className="text-sm text-slate-500">Normalized telemetry pipeline: SENSOR → INGEST → NORMALIZE → ENRICH → CORRELATE → DETECT</p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Events</div><div className="text-2xl font-bold">{events.data?.length ?? "…"}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Critical</div><div className="text-2xl font-bold text-critical">{counts.critical || 0}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">High</div><div className="text-2xl font-bold text-high">{counts.high || 0}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Deployed rules</div><div className="text-2xl font-bold text-low">{(rules.data || []).filter((r: any) => r.status === "DEPLOYED").length}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Draft rules</div><div className="text-2xl font-bold text-medium">{(rules.data || []).filter((r: any) => r.status === "DRAFT").length}</div></div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="Live Event Stream" right={<Badge tone="blue">NORMALIZED</Badge>}>
          <div className="max-h-[480px] space-y-1 overflow-y-auto">
            {events.isLoading && <Spinner />}
            {(events.data || []).map((e) => (
              <div key={e.id} className="flex items-start gap-2 rounded px-2 py-1 text-xs hover:bg-ink-800">
                <span className="mono w-32 shrink-0 text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <SeverityBadge severity={e.severity} />
                <div className="min-w-0">
                  <span className="mono text-slate-300">{e.event_type}</span>
                  <span className="ml-2 text-[10px] text-slate-500">{e.source}{e.demo ? " · LAB" : ""}</span>
                  {e.asset_id && <div className="mono text-[10px] text-slate-600">asset {e.asset_id.slice(0, 8)}</div>}
                </div>
              </div>
            ))}
            {events.data && !events.data.length && <Empty message="No events ingested" />}
          </div>
        </Card>

        <Card title="Detection Rules">
          <div className="space-y-1.5">
            {(rules.data || []).map((r) => (
              <div key={r.id} className="rounded border border-ink-700 bg-ink-800 px-3 py-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="mono text-xs font-medium text-accent">{r.rule_id}</span>
                    <span className="text-xs text-slate-200">{r.name}</span>
                  </div>
                  <Badge tone={r.status === "DEPLOYED" ? "green" : r.status === "DRAFT" ? "amber" : "slate"}>{r.status}</Badge>
                </div>
                <div className="mono mt-1 flex flex-wrap gap-1 text-[10px] text-slate-500">
                  <span>{r.source}</span>
                  <span>v{r.version}</span>
                  <span>{r.severity}</span>
                  {(r.mitre || []).map((m: string) => <span key={m} className="text-accent">{m}</span>)}
                  {r.regression_test && <Badge tone="blue">REGRESSION TEST</Badge>}
                </div>
                <div className="mono mt-1 text-[10px] text-slate-600">logic: {JSON.stringify(r.logic)}</div>
              </div>
            ))}
            {!rules.data?.length && <Empty message="No detection rules" />}
          </div>
        </Card>
      </div>
    </div>
  );
}
