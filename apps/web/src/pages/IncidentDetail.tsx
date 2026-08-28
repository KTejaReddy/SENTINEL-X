import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, DemoTag, Empty, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

const STATUSES = ["OPEN", "INVESTIGATING", "CONTAINED", "ERADICATION", "RECOVERY", "RESOLVED", "CLOSED"];
const ACTIONS = [
  { action_type: "CREATE_TICKET", name: "Create containment ticket", risk: "LOW", requires_approval: false },
  { action_type: "ENABLE_MONITORING", name: "Enable enhanced monitoring", risk: "MEDIUM", requires_approval: false },
  { action_type: "REVOKE_SESSION", name: "Revoke session", risk: "HIGH", requires_approval: true },
  { action_type: "DISABLE_ACCOUNT", name: "Disable account", risk: "HIGH", requires_approval: true },
  { action_type: "ISOLATE_ENDPOINT", name: "Isolate endpoint", risk: "CRITICAL", requires_approval: true },
  { action_type: "BLOCK_NETWORK", name: "Block network destination", risk: "CRITICAL", requires_approval: true },
  { action_type: "COLLECT_EVIDENCE", name: "Collect evidence", risk: "MEDIUM", requires_approval: false },
];

export default function IncidentDetail() {
  const { id } = useParams();
  const qc = useQueryClient();
  const incident = useQuery({ queryKey: ["incident", id], queryFn: () => api.get<any>(`/api/incidents/${id}`) });
  const timeline = useQuery({ queryKey: ["timeline", id], queryFn: () => api.get<any[]>(`/api/incidents/${id}/timeline`), refetchInterval: 5000 });
  const actions = useQuery({ queryKey: ["actions"], queryFn: () => api.get<any[]>("/api/responses/actions") });
  const playbooks = useQuery({ queryKey: ["playbooks"], queryFn: () => api.get<any[]>("/api/playbooks") });

  const update = useMutation({
    mutationFn: (body: any) => api.patch(`/api/incidents/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident", id] }),
  });
  const analyze = useMutation({
    mutationFn: () => api.post(`/api/incidents/${id}/analyze`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["incident", id] }),
  });
  const createAction = useMutation({
    mutationFn: (body: any) => api.post(`/api/responses/actions`, { incident_id: id, ...body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actions"] }),
  });
  const approve = useMutation({
    mutationFn: ({ actionId, approve: ok }: { actionId: string; approve: boolean }) => api.post(`/api/responses/actions/${actionId}/approve`, { approve: ok }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["actions"] }),
  });
  const execute = useMutation({
    mutationFn: (actionId: string) => api.post(`/api/responses/actions/${actionId}/execute`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["actions"] });
      qc.invalidateQueries({ queryKey: ["incident", id] });
    },
  });

  if (incident.isLoading) return <Spinner />;
  if (incident.error) return <div className="text-critical">{String(incident.error)}</div>;
  const i = incident.data;
  const incidentActions = (actions.data || []).filter((a: any) => a.incident_id === id);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-slate-100">{i.title}</h1>
          <SeverityBadge severity={i.severity} />
          <StatusBadge status={i.status} />
          {i.demo && <DemoTag />}
        </div>
        <Link to="/incidents" className="text-sm text-accent">← incidents</Link>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <select className="input w-44" value={i.status} onChange={(e) => update.mutate({ status: e.target.value })}>
          {STATUSES.map((s) => <option key={s}>{s}</option>)}
        </select>
        <button className="btn-ghost !py-1 text-xs" onClick={() => analyze.mutate()} disabled={analyze.isPending}>
          ✦ Run AI SOC analysis
        </button>
        {(i.attack_techniques || []).map((t: string) => <Badge key={t} tone="amber">{t}</Badge>)}
        {(i.detection_sources || []).map((s: string) => <Badge key={s} tone="blue">{s}</Badge>)}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Card title="Forensic Timeline" right={<span className="mono text-[10px] text-slate-500">links to raw evidence</span>}>
          <div className="max-h-[420px] space-y-0 overflow-y-auto">
            {(timeline.data || []).map((t, idx, arr) => (
              <div key={t.id} className="relative pl-6 pb-4">
                {idx < arr.length - 1 && <div className="absolute left-[7px] top-3 h-full w-px bg-ink-700" />}
                <div className={`absolute left-0 top-1.5 h-3.5 w-3.5 rounded-full border-2 ${t.kind === "DETECTION" ? "border-critical" : t.kind === "RESPONSE" ? "border-accent" : "border-ink-500"}`} />
                <div className="mono text-[10px] text-slate-500">{new Date(t.timestamp).toLocaleString()}</div>
                <div className="flex items-center gap-2">
                  <Badge tone={t.kind === "DETECTION" ? "red" : t.kind === "RESPONSE" ? "blue" : "slate"}>{t.kind}</Badge>
                  {t.event_id && <span className="mono text-[10px] text-slate-600">{t.event_id.slice(0, 12)}</span>}
                </div>
                <div className="text-xs text-slate-300">{t.message}</div>
              </div>
            ))}
            {!timeline.data?.length && <Empty message="No timeline entries" />}
          </div>
        </Card>

        <div className="space-y-4">
          <Card title="AI SOC Analysis" right={<button className="text-xs text-accent" onClick={() => analyze.mutate()}>re-analyze</button>}>
            {i.ai_analysis && i.ai_analysis.summary ? (
              <div className="space-y-2">
                <p className="text-sm text-slate-200">{i.ai_analysis.summary}</p>
                <div className="text-[10px] uppercase text-slate-500">Attack stage reached: <span className="text-accent">{i.ai_analysis.attack_stage}</span> · confidence {Math.round(i.ai_analysis.confidence * 100)}%</div>
                <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                  <div className="rounded border border-low/30 bg-low/5 p-2">
                    <div className="mb-1 text-[10px] font-bold uppercase text-low">Facts</div>
                    {(i.ai_analysis.facts || []).slice(0, 6).map((f: string, idx: number) => <div key={idx} className="text-[11px] text-slate-300">• {f}</div>)}
                  </div>
                  <div className="rounded border border-accent/30 bg-accent/5 p-2">
                    <div className="mb-1 text-[10px] font-bold uppercase text-accent">Inferences</div>
                    {(i.ai_analysis.inferences || []).map((f: string, idx: number) => <div key={idx} className="text-[11px] text-slate-300">• {f}</div>)}
                  </div>
                  <div className="rounded border border-medium/30 bg-medium/5 p-2">
                    <div className="mb-1 text-[10px] font-bold uppercase text-medium">Hypotheses</div>
                    {(i.ai_analysis.hypotheses || []).map((f: string, idx: number) => <div key={idx} className="text-[11px] text-slate-300">• {f}</div>)}
                  </div>
                  <div className="rounded border border-ink-600 bg-ink-800 p-2">
                    <div className="mb-1 text-[10px] font-bold uppercase text-slate-400">Recommendations</div>
                    {(i.ai_analysis.recommendations || []).map((f: string, idx: number) => <div key={idx} className="text-[11px] text-slate-300">• {f}</div>)}
                  </div>
                </div>
                <div className="text-[10px] text-slate-600">Facts come only from stored events/findings. Hypotheses are explicitly labeled as such.</div>
              </div>
            ) : (
              <Empty message="No AI analysis yet — run it to reconstruct the incident." />
            )}
          </Card>

          <Card title="Response Actions">
            <div className="mb-3 grid grid-cols-2 gap-1.5 md:grid-cols-3">
              {ACTIONS.map((a) => (
                <button key={a.action_type} className="rounded border border-ink-700 bg-ink-800 px-2 py-1.5 text-left text-[11px] hover:border-accent/40" onClick={() => createAction.mutate(a)}>
                  <div className="font-medium text-slate-200">{a.name}</div>
                  <div className="mt-0.5 flex items-center gap-1">
                    <Badge tone={a.risk === "CRITICAL" ? "red" : a.risk === "HIGH" ? "amber" : "slate"}>{a.risk}</Badge>
                    {a.requires_approval && <span className="text-[9px] text-medium">APPROVAL</span>}
                  </div>
                </button>
              ))}
            </div>
            <div className="space-y-1.5">
              {incidentActions.map((a) => (
                <div key={a.id} className="rounded border border-ink-700 bg-ink-800 px-3 py-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-200">{a.name}</span>
                      <Badge tone={a.risk_level === "CRITICAL" ? "red" : a.risk_level === "HIGH" ? "amber" : "slate"}>{a.risk_level}</Badge>
                      <Badge tone="blue">{a.action_type}</Badge>
                    </div>
                    <StatusBadge status={a.status} />
                  </div>
                  <div className="mt-1.5 flex gap-2">
                    {a.status === "PENDING_APPROVAL" && (
                      <>
                        <button className="btn-ghost !py-0.5 text-[11px]" onClick={() => approve.mutate({ actionId: a.id, approve: true })}>Approve</button>
                        <button className="btn-ghost !py-0.5 text-[11px]" onClick={() => approve.mutate({ actionId: a.id, approve: false })}>Reject</button>
                      </>
                    )}
                    {(a.status === "APPROVED" || !a.requires_approval) && a.status !== "EXECUTED" && (
                      <button className="btn-primary !py-0.5 text-[11px]" onClick={() => execute.mutate(a.id)}>Execute</button>
                    )}
                    {a.status === "EXECUTED" && <span className="mono text-[10px] text-slate-500">{a.result?.summary}</span>}
                  </div>
                </div>
              ))}
              {!incidentActions.length && <Empty message="No response actions yet" />}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
