import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, SeverityBadge, Spinner, Stat } from "../components/ui";

export default function AttackSurface() {
  const data = useQuery({ queryKey: ["attack-surface"], queryFn: () => api.get<any>("/api/attack-surface"), refetchInterval: 15000 });
  if (data.isLoading) return <Spinner label="Scanning attack surface…" />;
  if (data.error) return <div className="text-critical">{String(data.error)}</div>;
  const d = data.data;

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Attack Surface</h1>
        <p className="text-sm text-slate-500">External-facing exposure · change detection</p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Total Assets" value={d.total_assets} />
        <Stat label="Internet Exposed" value={d.internet_exposed} tone="critical" />
        <Stat label="New This Week" value={d.new_this_week} tone="accent" />
        <Stat label="Changed Today" value={d.changed_today} tone="medium" />
        <Stat label="Unmanaged" value={d.unmanaged} />
        <Stat label="High Risk" value={d.high_risk} tone="high" />
      </div>

      <Card title="Recent Changes (last 24h)" right={<Badge tone="blue">AUTO-DETECTED</Badge>}>
        <div className="space-y-1">
          {d.changes.map((c: any) => (
            <Link key={c.asset_id} to={`/assets/${c.asset_id}`} className="flex items-center justify-between rounded border border-ink-700 px-3 py-1.5 hover:bg-ink-800">
              <div>
                <span className="text-sm text-slate-200">{c.name}</span>
                <span className="mono ml-2 text-xs text-slate-500">{c.asset_type}</span>
              </div>
              <div className="flex items-center gap-2">
                <Badge tone={c.exposure === "INTERNET_FACING" ? "red" : "slate"}>{c.exposure}</Badge>
                <SeverityBadge severity={c.criticality} />
                <span className="mono text-[10px] text-slate-500">{new Date(c.changed_at).toLocaleString()}</span>
              </div>
            </Link>
          ))}
          {d.changes.length === 0 && <div className="py-6 text-center text-sm text-slate-500">No changes detected in the last 24h.</div>}
        </div>
      </Card>
    </div>
  );
}
