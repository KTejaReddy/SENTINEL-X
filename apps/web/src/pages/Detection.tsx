import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, Modal, Spinner, StatusBadge, Table } from "../components/ui";

export default function Detection() {
  const qc = useQueryClient();
  const rules = useQuery({ queryKey: ["rules"], queryFn: () => api.get<any[]>("/api/detections/rules") });
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ rule_id: "", name: "", severity: "high", status: "DRAFT", logic_type: "signature", match_event_type: "", threshold: 5 });

  const create = useMutation({
    mutationFn: () =>
      api.post("/api/detections/rules", {
        rule_id: form.rule_id,
        name: form.name,
        severity: form.severity,
        status: form.status,
        logic: form.logic_type === "threshold" ? { type: "threshold", match: { event_type: form.match_event_type }, threshold: Number(form.threshold), window_seconds: 300 } : { type: "signature", match: { event_type: form.match_event_type } },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["rules"] });
      setCreateOpen(false);
    },
  });
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: any }) => api.patch(`/api/detections/rules/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Detection Engineering</h1>
          <p className="text-sm text-slate-500">Sigma/Suricata/custom rules · versioned · regression-tested</p>
        </div>
        <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ New rule</button>
      </div>

      <Card>
        {rules.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["Rule", "Source", "Severity", "Version", "Status", "MITRE", "Logic"]}>
            {(rules.data || []).map((r) => (
              <tr key={r.id} className="hover:bg-ink-800/50">
                <td className="px-3 py-2">
                  <div className="mono text-xs font-medium text-accent">{r.rule_id}</div>
                  <div className="text-xs text-slate-300">{r.name}</div>
                </td>
                <td className="px-3 py-2 text-xs">{r.source}</td>
                <td className="px-3 py-2"><Badge tone={r.severity === "critical" ? "red" : r.severity === "high" ? "amber" : "slate"}>{r.severity}</Badge></td>
                <td className="mono px-3 py-2 text-xs">v{r.version}</td>
                <td className="px-3 py-2">
                  <select className="input !w-32 !py-1 text-xs" value={r.status} onChange={(e) => update.mutate({ id: r.id, body: { status: e.target.value } })}>
                    {["DRAFT", "TEST", "DEPLOYED", "DISABLED"].map((s) => <option key={s}>{s}</option>)}
                  </select>
                </td>
                <td className="px-3 py-2"><div className="flex flex-wrap gap-1">{(r.mitre || []).map((m: string) => <Badge key={m} tone="blue">{m}</Badge>)}</div></td>
                <td className="mono px-3 py-2 text-[10px] text-slate-500">{JSON.stringify(r.logic)}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New detection rule">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="label">Rule ID</label>
            <input className="input" placeholder="SIG-100" value={form.rule_id} onChange={(e) => setForm({ ...form, rule_id: e.target.value })} />
          </div>
          <div>
            <label className="label">Severity</label>
            <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {["low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div className="col-span-2">
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <label className="label">Logic type</label>
            <select className="input" value={form.logic_type} onChange={(e) => setForm({ ...form, logic_type: e.target.value })}>
              <option value="signature">signature</option>
              <option value="threshold">threshold</option>
            </select>
          </div>
          <div>
            <label className="label">Event type to match</label>
            <input className="input" placeholder="data:sensitive_access" value={form.match_event_type} onChange={(e) => setForm({ ...form, match_event_type: e.target.value })} />
          </div>
          {form.logic_type === "threshold" && (
            <div className="col-span-2">
              <label className="label">Threshold (events / 5 min)</label>
              <input className="input" type="number" value={form.threshold} onChange={(e) => setForm({ ...form, threshold: Number(e.target.value) })} />
            </div>
          )}
        </div>
        <button className="btn-primary mt-4" disabled={!form.rule_id || !form.name} onClick={() => create.mutate()}>Create (DRAFT)</button>
      </Modal>
    </div>
  );
}
