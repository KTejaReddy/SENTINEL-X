import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, Spinner, StatusBadge, Table } from "../components/ui";

export default function Response() {
  const qc = useQueryClient();
  const playbooks = useQuery({ queryKey: ["playbooks"], queryFn: () => api.get<any[]>("/api/playbooks") });
  const actions = useQuery({ queryKey: ["actions"], queryFn: () => api.get<any[]>("/api/responses/actions"), refetchInterval: 6000 });

  const approve = useMutation({
    mutationFn: ({ id, approve: ok }: { id: string; approve: boolean }) => api.post(`/api/responses/actions/${id}/approve`, { approve: ok }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actions"] }),
  });
  const execute = useMutation({
    mutationFn: (id: string) => api.post(`/api/responses/actions/${id}/execute`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actions"] }),
  });

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Automated Response</h1>
        <p className="text-sm text-slate-500">Human approval model: LOW auto · MEDIUM monitored · HIGH/CRITICAL require approval · adapters only, no raw commands</p>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Playbooks" className="xl:col-span-1">
          <div className="space-y-2">
            {(playbooks.data || []).map((p) => (
              <div key={p.id} className="rounded border border-ink-700 bg-ink-800 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-200">{p.name}</span>
                  <StatusBadge status={p.status} />
                </div>
                <div className="mt-1 text-xs text-slate-500">{p.description}</div>
                <div className="mono mt-2 text-[10px] text-slate-600">trigger: {JSON.stringify(p.triggers)}</div>
              </div>
            ))}
            {!playbooks.data?.length && <Empty message="No playbooks" />}
          </div>
        </Card>

        <Card title="Response Actions" className="xl:col-span-2" right={<Badge tone="amber">APPROVAL REQUIRED: HIGH/CRITICAL</Badge>}>
          <Table headers={["Action", "Risk", "Status", "Target", "Incident", "Result"]}>
            {(actions.data || []).map((a) => (
              <tr key={a.id} className="hover:bg-ink-800/50">
                <td className="px-3 py-2">
                  <div className="text-xs font-medium text-slate-200">{a.name}</div>
                  <div className="mono text-[10px] text-slate-500">{a.action_type}</div>
                </td>
                <td className="px-3 py-2"><Badge tone={a.risk_level === "CRITICAL" ? "red" : a.risk_level === "HIGH" ? "amber" : a.risk_level === "MEDIUM" ? "slate" : "green"}>{a.risk_level}</Badge></td>
                <td className="px-3 py-2"><StatusBadge status={a.status} /></td>
                <td className="mono px-3 py-2 text-[10px] text-slate-500">{JSON.stringify(a.target)}</td>
                <td className="px-3 py-2">
                  {a.incident_id ? <Link to={`/incidents/${a.incident_id}`} className="mono text-xs text-accent">{a.incident_id.slice(0, 8)}</Link> : "—"}
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-1.5">
                    {a.status === "PENDING_APPROVAL" && (
                      <>
                        <button className="btn-ghost !py-0.5 text-[11px]" onClick={() => approve.mutate({ id: a.id, approve: true })}>Approve</button>
                        <button className="btn-ghost !py-0.5 text-[11px]" onClick={() => approve.mutate({ id: a.id, approve: false })}>Reject</button>
                      </>
                    )}
                    {(a.status === "APPROVED" || !a.requires_approval) && a.status !== "EXECUTED" && (
                      <button className="btn-primary !py-0.5 text-[11px]" onClick={() => execute.mutate(a.id)}>Execute</button>
                    )}
                    {a.status === "EXECUTED" && <span className="mono max-w-[200px] truncate text-[10px] text-slate-500">{a.result?.summary}</span>}
                  </div>
                </td>
              </tr>
            ))}
          </Table>
          {!actions.data?.length && <Empty message="No response actions" />}
        </Card>
      </div>
    </div>
  );
}
