import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, Progress, SeverityBadge, Spinner, StatusBadge, Table } from "../components/ui";

export default function EngagementDetail() {
  const { id } = useParams();
  const qc = useQueryClient();
  const eng = useQuery({ queryKey: ["engagement", id], queryFn: () => api.get<any>(`/api/engagements/${id}`) });
  const jobs = useQuery({ queryKey: ["engagement-jobs", id], queryFn: () => api.get<any[]>(`/api/jobs?engagement_id=${id}&size=100`), refetchInterval: 4000 });
  const findings = useQuery({ queryKey: ["engagement-findings", id], queryFn: () => api.get<any[]>(`/api/findings?size=200`) });

  const action = useMutation({
    mutationFn: ({ act }: { act: string }) => api.post(`/api/engagements/${id}/${act}`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["engagement", id] }),
  });

  const checkScope = useMutation({
    mutationFn: (target: string) => api.post(`/api/engagements/${id}/check-scope`, { target }),
  });

  if (eng.isLoading) return <Spinner />;
  if (eng.error) return <div className="text-critical">{String(eng.error)}</div>;
  const e = eng.data;

  const lifecycle: [string, string][] = [
    ["submit", "PENDING_APPROVAL"],
    ["approve", "APPROVED"],
    ["start", "RUNNING"],
    ["pause", "PAUSED"],
    ["close", "CLOSED"],
  ];

  const allowed = (act: string) => {
    const next: Record<string, string[]> = {
      submit: ["DRAFT"],
      approve: ["PENDING_APPROVAL"],
      start: ["APPROVED", "PAUSED"],
      pause: ["RUNNING"],
      close: ["APPROVED", "RUNNING", "PAUSED"],
    };
    return (next[act] || []).includes(e.status);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">{e.name}</h1>
          <p className="text-sm text-slate-500">{e.description}</p>
        </div>
        <StatusBadge status={e.status} />
      </div>

      <div className="flex flex-wrap gap-2">
        {lifecycle.map(([act, label]) => (
          <button key={act} className="btn-ghost !py-1 text-xs" disabled={!allowed(act) || action.isPending} onClick={() => action.mutate({ act })}>
            {label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Authorized Scope">
          <div className="space-y-1">
            {e.scope_rules.map((r: any) => (
              <div key={r.id} className="mono flex items-center justify-between rounded border border-ink-700 px-2 py-1 text-xs">
                <span className={r.kind === "INCLUDE" ? "text-low" : "text-critical"}>{r.kind}</span>
                <span className="text-slate-300">{r.value}</span>
              </div>
            ))}
            {!e.scope_rules.length && <Empty message="No scope rules — add some before submitting" />}
          </div>
          <div className="mt-3 flex gap-2">
            <input id="scope-probe" className="input flex-1" placeholder="Probe a target, e.g. 8.8.8.8" />
            <button className="btn-ghost text-xs" onClick={() => {
              const input = document.getElementById("scope-probe") as HTMLInputElement;
              if (input.value) checkScope.mutate(input.value);
            }}>
              Check scope
            </button>
          </div>
          {checkScope.data && (
            <div className={`mt-2 rounded border px-2 py-1 text-xs ${checkScope.data.allowed ? "border-low/40 bg-low/10 text-low" : "border-critical/40 bg-critical/10 text-critical"}`}>
              {checkScope.data.allowed ? "IN SCOPE ✓" : `DENIED — ${checkScope.data.reason}`}
            </div>
          )}
        </Card>

        <Card title="Policy Configuration">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <div className="text-[10px] uppercase text-slate-500">Allowed tools</div>
              <div className="mt-1 flex flex-wrap gap-1">{(e.config.allowed_tools || []).map((t: string) => <Badge key={t}>{t}</Badge>)}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase text-slate-500">Max request rate</div>
              <div className="mono text-slate-200">{e.config.max_request_rate}/min</div>
            </div>
            <div>
              <div className="text-[10px] uppercase text-slate-500">Destructive testing</div>
              <div className={e.config.destructive_testing ? "text-critical" : "text-low"}>{e.config.destructive_testing ? "PERMITTED" : "BLOCKED"}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase text-slate-500">Data handling</div>
              <div className="mono text-slate-200">{e.config.data_handling}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase text-slate-500">Approved by</div>
              <div className="mono text-slate-200">{e.approved_by || "—"}</div>
            </div>
            <div>
              <div className="text-[10px] uppercase text-slate-500">Window</div>
              <div className="mono text-slate-200">{e.start_date || "—"} → {e.end_date || "—"}</div>
            </div>
          </div>
        </Card>

        <Card title="Run assessment">
          <p className="mb-2 text-xs text-slate-500">Queue an authorized scan through the policy engine. Use the lab-range adapter for controlled replays (10.10.10.0/24).</p>
          <label className="label">Target</label>
          <input id="job-target" className="input" defaultValue="10.10.10.10" />
          <div className="mt-2 flex gap-2">
            <button
              className="btn-primary flex-1"
              disabled={e.status !== "APPROVED" && e.status !== "RUNNING"}
              onClick={() => {
                const target = (document.getElementById("job-target") as HTMLInputElement).value;
                api.post("/api/jobs", { engagement_id: e.id, kind: "scan", tool: "lab-range", target_ref: target, params: { scenario: "web_app_authorization" } }).then(() => qc.invalidateQueries({ queryKey: ["engagement-jobs", id] }));
              }}
            >
              Run lab-range scan
            </button>
          </div>
        </Card>
      </div>

      <Card title="Jobs">
        <div className="space-y-1.5">
          {(jobs.data || []).map((j) => (
            <div key={j.id} className="rounded border border-ink-700 bg-ink-800 px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Badge tone="blue">{j.kind}</Badge>
                  <span className="mono text-xs text-slate-300">{j.tool}</span>
                  <span className="mono text-[10px] text-slate-500">{j.target_ref}</span>
                </div>
                <StatusBadge status={j.status} />
              </div>
              <Progress value={j.progress} tone={j.status === "failed" ? "red" : j.status === "completed" ? "green" : "accent"} />
              {j.error && <div className="mono mt-1 text-[11px] text-critical">{j.error}</div>}
            </div>
          ))}
          {!jobs.data?.length && <Empty message="No jobs for this engagement" />}
        </div>
      </Card>

      <Card title="Findings from this engagement">
        <Table headers={["ID", "Finding", "Severity", "CVSS", "Status", "Validated"]}>
          {(findings.data || [])
            .filter((f: any) => f.engagement_id === e.id)
            .map((f: any) => (
              <tr key={f.id} className="hover:bg-ink-800/50">
                <td className="mono px-3 py-2 text-xs text-slate-500">{f.id.slice(0, 8)}</td>
                <td className="px-3 py-2 text-slate-200">{f.title}</td>
                <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                <td className="mono px-3 py-2 text-xs">{f.cvss ?? "—"}</td>
                <td className="px-3 py-2"><StatusBadge status={f.status} /></td>
                <td className="px-3 py-2 text-xs">{f.validated ? "✓" : "—"}</td>
              </tr>
            ))}
        </Table>
      </Card>
    </div>
  );
}
