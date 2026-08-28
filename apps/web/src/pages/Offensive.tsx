import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, DemoTag, Empty, Modal, Progress, Spinner, StatusBadge, Table } from "../components/ui";

export default function Offensive() {
  const [tab, setTab] = useState<"engagements" | "jobs" | "tools">("engagements");
  const qc = useQueryClient();

  const engagements = useQuery({ queryKey: ["engagements"], queryFn: () => api.get<any[]>("/api/engagements") });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.get<any[]>("/api/jobs?size=100"), refetchInterval: 4000 });
  const tools = useQuery({ queryKey: ["tools"], queryFn: () => api.get<any[]>("/api/tools") });

  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ name: "", description: "", start_date: "", end_date: "", cidr: "" });
  const createEngagement = useMutation({
    mutationFn: (body: any) =>
      api.post("/api/engagements", {
        name: body.name,
        description: body.description,
        start_date: body.start_date || null,
        end_date: body.end_date || null,
        scope_rules: body.cidr ? [{ kind: "INCLUDE", match_type: "CIDR", value: body.cidr }] : [],
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["engagements"] });
      setCreateOpen(false);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Offensive Security</h1>
          <p className="text-sm text-slate-500">Authorized engagements · scope-gated tool execution</p>
        </div>
        <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ New engagement</button>
      </div>

      <div className="flex gap-1">
        {(["engagements", "jobs", "tools"] as const).map((t) => (
          <button key={t} className={`tab ${tab === t ? "tab-active" : ""}`} onClick={() => setTab(t)}>
            {t.toUpperCase()}
          </button>
        ))}
      </div>

      {tab === "engagements" && (
        <Card title="Engagements" right={<DemoTag />}>
          {engagements.isLoading ? (
            <Spinner />
          ) : (
            <Table headers={["Engagement", "Status", "Scope", "Tools", "Created", ""]}>
              {(engagements.data || []).map((e) => (
                <tr key={e.id} className="hover:bg-ink-800/50">
                  <td className="px-3 py-2">
                    <Link to={`/offensive/${e.id}`} className="font-medium text-accent hover:underline">{e.name}</Link>
                    {e.description && <div className="max-w-md truncate text-[11px] text-slate-500">{e.description}</div>}
                  </td>
                  <td className="px-3 py-2"><StatusBadge status={e.status} /></td>
                  <td className="px-3 py-2">
                    <div className="mono text-xs text-slate-300">
                      {e.scope_rules.filter((r: any) => r.kind === "INCLUDE").map((r: any) => r.value).join(", ") || "—"}
                    </div>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">{(e.config.allowed_tools || []).map((t: string) => <Badge key={t}>{t}</Badge>)}</div>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500">{new Date(e.created_at).toLocaleDateString()}</td>
                  <td className="px-3 py-2 text-right"><Link to={`/offensive/${e.id}`} className="text-xs text-accent">open →</Link></td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      )}

      {tab === "jobs" && (
        <Card title="Job Queue" right={<span className="mono text-xs text-slate-500">worker: db-poll · live</span>}>
          <div className="space-y-1.5">
            {(jobs.data || []).map((j) => (
              <div key={j.id} className="rounded border border-ink-700 bg-ink-800 px-3 py-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge tone="blue">{j.kind}</Badge>
                    <span className="mono text-xs text-slate-300">{j.tool}</span>
                    <span className="mono text-[10px] text-slate-500">{j.target_ref || "—"}</span>
                    {j.demo && <Badge tone="blue">LAB</Badge>}
                  </div>
                  <div className="flex items-center gap-3">
                    <StatusBadge status={j.status} />
                    <span className="mono text-[10px] text-slate-500">{new Date(j.created_at).toLocaleTimeString()}</span>
                    <Link className="text-xs text-accent" to={`/offensive/${j.engagement_id}`}>engagement</Link>
                  </div>
                </div>
                <Progress value={j.progress} tone={j.status === "failed" ? "red" : j.status === "completed" ? "green" : "accent"} />
                {j.error && <div className="mono mt-1 text-[11px] text-critical">{j.error}</div>}
                {j.result && j.result.findings_created != null && (
                  <div className="mono mt-1 text-[10px] text-slate-500">
                    findings +{j.result.findings_created} (~{j.result.findings_updated} updated) · events {j.result.events}
                    {j.result.retest ? ` · retest ${j.result.retest.status}` : ""}
                  </div>
                )}
              </div>
            ))}
            {!jobs.data?.length && <Empty message="No jobs yet — create an engagement and run a scan" />}
          </div>
        </Card>
      )}

      {tab === "tools" && (
        <Card title="Tool Adapters" right={<span className="mono text-xs text-slate-500">health: live probe</span>}>
          <Table headers={["Adapter", "Category", "Status", "Version", "Description"]}>
            {(tools.data || []).map((t) => (
              <tr key={t.id} className="hover:bg-ink-800/50">
                <td className="mono px-3 py-2 font-medium text-slate-200">{t.name}</td>
                <td className="px-3 py-2 text-xs text-slate-400">{t.category}</td>
                <td className="px-3 py-2"><Badge tone={t.health === "OK" ? "green" : "amber"}>{t.health}</Badge></td>
                <td className="mono px-3 py-2 text-xs text-slate-500">{t.version || "—"}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{t.metadata_json?.description || ""}</td>
              </tr>
            ))}
          </Table>
          <p className="mt-3 text-xs text-slate-500">
            Tools not installed locally report <span className="mono text-amber">NOT_INSTALLED</span> and never crash the platform. The{" "}
            <span className="mono text-accent">lab-range</span> adapter provides controlled replays for the cyber-range (10.10.10.0/24) through the same pipeline.
          </p>
        </Card>
      )}

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New engagement" wide>
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div className="col-span-2">
            <label className="label">Description</label>
            <textarea className="input" rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <div>
            <label className="label">Start date</label>
            <input className="input" type="date" value={form.start_date} onChange={(e) => setForm({ ...form, start_date: e.target.value })} />
          </div>
          <div>
            <label className="label">End date</label>
            <input className="input" type="date" value={form.end_date} onChange={(e) => setForm({ ...form, end_date: e.target.value })} />
          </div>
          <div className="col-span-2">
            <label className="label">Authorized scope (CIDR — e.g. 10.10.10.0/24)</label>
            <input className="input" placeholder="10.10.10.0/24" value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} />
          </div>
        </div>
        <p className="mt-2 text-[11px] text-slate-500">The scope engine will reject any target outside this range. Exclude rules can be added after creation.</p>
        <button className="btn-primary mt-4" disabled={!form.name} onClick={() => createEngagement.mutate(form)}>
          Create engagement (DRAFT)
        </button>
      </Modal>
    </div>
  );
}
