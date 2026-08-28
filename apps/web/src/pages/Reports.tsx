import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, Empty, Modal, Spinner, StatusBadge, Table } from "../components/ui";

const TYPES = [
  { id: "executive", label: "Executive Report" },
  { id: "pentest", label: "Pentest Report" },
  { id: "bug_bounty", label: "Bug Bounty Report" },
  { id: "soc_incident", label: "SOC Incident Report" },
  { id: "purple", label: "Purple Team Report" },
  { id: "remediation", label: "Remediation Report" },
];

export default function Reports() {
  const qc = useQueryClient();
  const reports = useQuery({ queryKey: ["reports"], queryFn: () => api.get<any[]>("/api/reports") });
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: () => api.get<any[]>("/api/engagements") });
  const [genOpen, setGenOpen] = useState(false);
  const [type, setType] = useState("executive");
  const [engagementId, setEngagementId] = useState("");
  const [view, setView] = useState<any>(null);

  const generate = useMutation({
    mutationFn: () => api.post("/api/reports/generate", { report_type: type, engagement_id: engagementId || null }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["reports"] });
      setGenOpen(false);
      setView(res);
    },
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Reporting</h1>
          <p className="text-sm text-slate-500">Executive · pentest · purple · incident · remediation — rendered from stored evidence only</p>
        </div>
        <button className="btn-primary" onClick={() => setGenOpen(true)}>+ Generate report</button>
      </div>

      <Card>
        {reports.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["Report", "Type", "Status", "Format", "Generated", ""]}>
            {(reports.data || []).map((r) => (
              <tr key={r.id} className="hover:bg-ink-800/50">
                <td className="px-3 py-2 text-sm font-medium text-slate-200">{r.title}</td>
                <td className="px-3 py-2"><Badge tone="blue">{r.report_type}</Badge></td>
                <td className="px-3 py-2"><StatusBadge status={r.status} /></td>
                <td className="mono px-3 py-2 text-xs">{r.format}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{new Date(r.generated_at).toLocaleString()}</td>
                <td className="px-3 py-2 text-right">
                  <button className="text-xs text-accent" onClick={() => api.get(`/api/reports/${r.id}`).then(setView)}>view →</button>
                </td>
              </tr>
            ))}
          </Table>
        )}
        {reports.data && !reports.data.length && <Empty message="No reports generated" />}
      </Card>

      <Modal open={genOpen} onClose={() => setGenOpen(false)} title="Generate report">
        <div className="space-y-3">
          <div>
            <label className="label">Report type</label>
            <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
              {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Engagement (optional scope)</label>
            <select className="input" value={engagementId} onChange={(e) => setEngagementId(e.target.value)}>
              <option value="">— none —</option>
              {(engagements.data || []).map((e: any) => <option key={e.id} value={e.id}>{e.name}</option>)}
            </select>
          </div>
          <button className="btn-primary" disabled={generate.isPending} onClick={() => generate.mutate()}>
            Generate
          </button>
        </div>
      </Modal>

      <Modal open={!!view} onClose={() => setView(null)} title={view?.title || "Report"} wide>
        {view && (
          <div>
            <div className="mb-2 flex gap-2">
              <a className="btn-ghost !py-1 text-xs" href={`/api/reports/${view.id}/export?fmt=markdown`}>Markdown</a>
              <a className="btn-ghost !py-1 text-xs" href={`/api/reports/${view.id}/export?fmt=html`}>HTML</a>
              <a className="btn-ghost !py-1 text-xs" href={`/api/reports/${view.id}/export?fmt=json`}>JSON</a>
              <a className="btn-ghost !py-1 text-xs" href={`/api/reports/${view.id}/export?fmt=csv`}>CSV</a>
            </div>
            <pre className="mono max-h-[60vh] overflow-auto rounded bg-ink-900 p-3 text-[11px] leading-relaxed text-slate-300">{view.markdown}</pre>
          </div>
        )}
      </Modal>
    </div>
  );
}
