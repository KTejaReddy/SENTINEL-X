import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

export default function AssetDetail() {
  const { id } = useParams();
  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => api.get<any>(`/api/assets/${id}`) });
  const services = useQuery({ queryKey: ["asset-services", id], queryFn: () => api.get<any[]>(`/api/assets/${id}/services`) });
  const rels = useQuery({ queryKey: ["asset-rels", id], queryFn: () => api.get<any[]>(`/api/assets/${id}/relationships`) });
  const findings = useQuery({ queryKey: ["asset-findings", id], queryFn: () => api.get<any[]>(`/api/findings?asset_id=${id}`) });

  if (asset.isLoading) return <Spinner />;
  if (asset.error) return <div className="text-critical">{String(asset.error)}</div>;
  const a = asset.data;

  const summary: [string, any][] = [
    ["Asset type", a.asset_type],
    ["Owner", a.owner || "—"],
    ["Environment", a.environment || "—"],
    ["Criticality", a.criticality],
    ["Zone", a.zone || "—"],
    ["IP", a.ip_address || "—"],
    ["DNS", a.dns_name || "—"],
    ["Technology", a.technology || "—"],
    ["OS", a.os || "—"],
    ["Exposure", a.exposure],
    ["Managed", a.managed ? "yes" : "no"],
    ["Status", a.status],
    ["Source", a.source],
    ["Last seen", a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"],
  ];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-slate-100">{a.name}</h1>
          <Badge tone={a.exposure === "INTERNET_FACING" ? "red" : "slate"}>{a.exposure}</Badge>
          <SeverityBadge severity={a.criticality} />
          {a.metadata_json?.label && <Badge tone="blue">{a.metadata_json.label}</Badge>}
        </div>
        <Link to="/assets" className="text-sm text-accent">← all assets</Link>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Asset Profile">
          <div className="grid grid-cols-2 gap-2">
            {summary.map(([k, v]) => (
              <div key={k}>
                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{k}</div>
                <div className="mono text-xs text-slate-200">{v}</div>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Services">
          {services.data?.length ? (
            <div className="space-y-1">
              {services.data.map((s: any) => (
                <div key={s.id} className="mono flex items-center justify-between rounded border border-ink-700 px-2 py-1 text-xs">
                  <span className="text-slate-200">{s.name}</span>
                  <span className="text-slate-500">{s.port ? `:${s.port}` : ""} {s.version || ""}</span>
                </div>
              ))}
            </div>
          ) : (
            <Empty message="No services recorded" />
          )}
        </Card>

        <Card title="Relationships">
          <div className="space-y-1">
            {rels.data?.map((r: any) => (
              <div key={r.id} className="mono flex items-center justify-between rounded border border-ink-700 px-2 py-1 text-xs">
                <span className="truncate text-slate-300">{r.source_asset_id === id ? "this →" : "← this"}</span>
                <Badge>{r.relationship_type}</Badge>
                <span className="truncate text-slate-500">{r.source_asset_id === id ? r.target_asset_id.slice(0, 8) : r.source_asset_id.slice(0, 8)}</span>
              </div>
            ))}
            {!rels.data?.length && <Empty message="No relationships" />}
          </div>
        </Card>
      </div>

      <Card title="Findings on this asset">
        <div className="space-y-1">
          {(findings.data || []).map((f: any) => (
            <Link key={f.id} to={`/vulnerabilities/${f.id}`} className="flex items-center justify-between rounded border border-ink-700 px-3 py-1.5 hover:bg-ink-800">
              <div className="min-w-0">
                <div className="truncate text-sm text-slate-200">{f.title}</div>
                <div className="mono text-[10px] text-slate-500">{f.cve || ""} {f.cwe || ""} · {f.category || ""}</div>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <StatusBadge status={f.status} />
              </div>
            </Link>
          ))}
          {!findings.data?.length && <Empty message="No findings" />}
        </div>
      </Card>
    </div>
  );
}
