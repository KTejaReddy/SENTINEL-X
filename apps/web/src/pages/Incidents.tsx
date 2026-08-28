import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Modal, SeverityBadge, Spinner, StatusBadge, Table } from "../components/ui";

export default function Incidents() {
  const incidents = useQuery({ queryKey: ["incidents"], queryFn: () => api.get<any[]>("/api/incidents"), refetchInterval: 8000 });
  const [createOpen, setCreateOpen] = useState(false);
  const [form, setForm] = useState({ title: "", severity: "medium", description: "" });
  const qc = useQueryClient();
  const create = useMutation({
    mutationFn: () => api.post("/api/incidents", form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["incidents"] });
      setCreateOpen(false);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Incidents</h1>
          <p className="text-sm text-slate-500">Detected · investigated · contained · resolved</p>
        </div>
        <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ Incident</button>
      </div>

      <Card>
        {incidents.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["ID", "Incident", "Severity", "Status", "Techniques", "Created"]}>
            {(incidents.data || []).map((i) => (
              <tr key={i.id} className="hover:bg-ink-800/50">
                <td className="mono px-3 py-2 text-xs text-slate-500">{i.id.slice(0, 8)}</td>
                <td className="px-3 py-2">
                  <Link to={`/incidents/${i.id}`} className="font-medium text-accent hover:underline">{i.title}</Link>
                </td>
                <td className="px-3 py-2"><SeverityBadge severity={i.severity} /></td>
                <td className="px-3 py-2"><StatusBadge status={i.status} /></td>
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">{(i.attack_techniques || []).map((t: string) => <Badge key={t}>{t}</Badge>)}</div>
                </td>
                <td className="px-3 py-2 text-xs text-slate-500">{new Date(i.created_at).toLocaleString()}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New incident">
        <div className="space-y-3">
          <div>
            <label className="label">Title</label>
            <input className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          </div>
          <div>
            <label className="label">Severity</label>
            <select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {["critical", "high", "medium", "low"].map((s) => <option key={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Description</label>
            <textarea className="input" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <button className="btn-primary" disabled={!form.title} onClick={() => create.mutate()}>Create</button>
        </div>
      </Modal>
    </div>
  );
}
