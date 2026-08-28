import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, DemoTag, Empty, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

export default function FindingDetail() {
  const { id } = useParams();
  const qc = useQueryClient();
  const finding = useQuery({ queryKey: ["finding", id], queryFn: () => api.get<any>(`/api/findings/${id}`) });
  const evidence = useQuery({ queryKey: ["finding-evidence", id], queryFn: () => api.get<any[]>("/api/evidence") });
  const retests = useQuery({ queryKey: ["retests"], queryFn: () => api.get<any[]>("/api/retests") });

  const mutate = useMutation({
    mutationFn: (body: any) => api.patch(`/api/findings/${id}`, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });
  const triage = useMutation({
    mutationFn: () => api.post(`/api/ai/triage`, { finding_id: id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });
  const validate = useMutation({
    mutationFn: () => api.post(`/api/findings/${id}/validate`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });
  const retest = useMutation({
    mutationFn: async () => {
      await api.post("/api/remediation", { finding_id: id });
      const rs = await api.get<any[]>("/api/remediation");
      const rem = rs.find((r: any) => r.finding_id === id);
      if (rem) await api.post(`/api/remediation/${rem.id}/verify`, {});
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["retests"] });
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
  });

  if (finding.isLoading) return <Spinner />;
  if (finding.error) return <div className="text-critical">{String(finding.error)}</div>;
  const f = finding.data;
  const myEvidence = (evidence.data || []).filter((e: any) => e.finding_id === id || (f.evidence_refs || []).includes(e.id));
  const myRetests = (retests.data || []).filter((r: any) => r.finding_id === id);

  const statusOptions = ["NEW", "TRIAGED", "VALIDATING", "VALIDATED", "RISK_ACCEPTED", "REMEDIATION", "FIXED", "RETESTING", "VERIFIED", "CLOSED"];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-slate-100">{f.title}</h1>
          <SeverityBadge severity={f.severity} />
          <StatusBadge status={f.status} />
          {f.demo && <DemoTag />}
        </div>
        <Link to="/vulnerabilities" className="text-sm text-accent">← findings</Link>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Details">
          <div className="grid grid-cols-2 gap-2 text-xs">
            {[
              ["ID", f.id.slice(0, 12)],
              ["CVSS", f.cvss ?? "—"],
              ["CVE", f.cve || "—"],
              ["CWE", f.cwe || "—"],
              ["Category", f.category || "—"],
              ["Source", f.source],
              ["Confidence", f.confidence],
              ["Validated", f.validated ? "yes" : "no"],
              ["Exploitability", f.exploitability],
              ["Endpoint", f.endpoint || "—"],
              ["Owner", f.owner || "—"],
              ["Due", f.due_date || "—"],
            ].map(([k, v]) => (
              <div key={k}>
                <div className="text-[10px] uppercase text-slate-500">{k}</div>
                <div className="mono break-all text-slate-200">{String(v)}</div>
              </div>
            ))}
          </div>
          {f.description && (
            <div className="mt-3 border-t border-ink-700 pt-3 text-xs leading-relaxed text-slate-400">{f.description}</div>
          )}
          {f.remediation && (
            <div className="mt-3 border-t border-ink-700 pt-3">
              <div className="mb-1 text-[10px] uppercase text-slate-500">Recommended remediation</div>
              <div className="text-xs text-slate-300">{f.remediation}</div>
            </div>
          )}
        </Card>

        <Card title="AI Triage" right={<button className="text-xs text-accent" onClick={() => triage.mutate()}>re-analyze</button>}>
          {f.ai_triage && Object.keys(f.ai_triage).length ? (
            <div className="space-y-2">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><div className="text-[10px] uppercase text-slate-500">Classification</div><span className="text-accent">{f.ai_triage.classification}</span></div>
                <div><div className="text-[10px] uppercase text-slate-500">Business risk</div><SeverityBadge severity={f.ai_triage.business_risk} /></div>
                <div><div className="text-[10px] uppercase text-slate-500">Asset criticality</div><span>{f.ai_triage.asset_criticality}</span></div>
                <div><div className="text-[10px] uppercase text-slate-500">Confidence</div><span>{Math.round(f.ai_triage.confidence * 100)}%</span></div>
                <div className="col-span-2"><div className="text-[10px] uppercase text-slate-500">Attack path relevant</div><span>{f.ai_triage.likely_attack_path ? "yes" : "no"}</span></div>
              </div>
              {f.ai_triage.evidence_required?.length > 0 && (
                <div className="rounded border border-amber/40 bg-amber/5 p-2">
                  <div className="mb-1 text-[10px] uppercase text-slate-500">Evidence required before validation</div>
                  {f.ai_triage.evidence_required.map((r: string) => <div key={r} className="text-[11px] text-slate-300">• {r}</div>)}
                </div>
              )}
              <div className="mono text-[10px] text-slate-500">validated output · never fabricated from unsupported evidence</div>
            </div>
          ) : (
            <Empty message="Run AI triage to classify this finding against real evidence." />
          )}
        </Card>

        <Card title="Lifecycle actions">
          <label className="label">Status</label>
          <select className="input" value={f.status} onChange={(e) => mutate.mutate({ status: e.target.value })}>
            {statusOptions.map((s) => <option key={s}>{s}</option>)}
          </select>
          <div className="mt-3 space-y-2">
            <button className="btn-primary w-full" disabled={validate.isPending} onClick={() => validate.mutate()}>
              Request controlled validation
            </button>
            <button className="btn-ghost w-full" onClick={() => retest.mutate()} disabled={retest.isPending}>
              Create remediation + verify (retest)
            </button>
            <p className="text-[11px] text-slate-500">
              Validation runs only through an approved engagement with the policy engine; retest moves the finding to VERIFIED only when the vulnerability is no longer reported.
            </p>
          </div>
        </Card>
      </div>

      <Card title="Evidence" right={<Link className="text-xs text-accent" to="/evidence">vault</Link>}>
        <div className="space-y-1.5">
          {myEvidence.map((e: any) => (
            <div key={e.id} className="rounded border border-ink-700 bg-ink-800 px-3 py-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Badge tone="blue">{e.kind}</Badge>
                  <span className="mono text-xs text-slate-300">{e.tool}</span>
                  {e.demo && <Badge tone="blue">LAB</Badge>}
                </div>
                <span className="mono text-[10px] text-slate-500">sha256 {e.content_hash.slice(0, 12)}…</span>
              </div>
              <pre className="mono mt-1 max-h-32 overflow-auto rounded bg-ink-900 p-2 text-[10px] text-slate-400">{JSON.stringify(e.data, null, 1)}</pre>
            </div>
          ))}
          {!myEvidence.length && <Empty message="No evidence captured yet — run validation or a scan" />}
        </div>
      </Card>

      <Card title="Retests">
        <div className="space-y-1.5">
          {myRetests.map((r: any) => (
            <div key={r.id} className="flex items-center justify-between rounded border border-ink-700 px-3 py-2">
              <div className="mono text-xs text-slate-300">retest {r.id.slice(0, 8)} · {new Date(r.created_at).toLocaleString()}</div>
              <StatusBadge status={r.status} />
            </div>
          ))}
          {!myRetests.length && <Empty message="No retests for this finding" />}
        </div>
      </Card>
    </div>
  );
}
