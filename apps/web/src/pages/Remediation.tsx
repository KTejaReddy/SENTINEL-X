import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner, StatusBadge, Table } from "../components/ui";

export default function Remediation() {
  const qc = useQueryClient();
  const remediation = useQuery({ queryKey: ["remediation"], queryFn: () => api.get<any[]>("/api/remediation"), refetchInterval: 8000 });
  const retests = useQuery({ queryKey: ["retests"], queryFn: () => api.get<any[]>("/api/retests"), refetchInterval: 8000 });
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => api.get<any[]>("/api/findings?size=200") });

  const verify = useMutation({
    mutationFn: (id: string) => api.post(`/api/remediation/${id}/verify`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["remediation"] });
      qc.invalidateQueries({ queryKey: ["retests"] });
    },
  });

  const findingMap = new Map((findings.data || []).map((f: any) => [f.id, f]));
  const retestMap = new Map((retests.data || []).map((r: any) => [r.finding_id, r]));

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Remediation & Retest</h1>
        <p className="text-sm text-slate-500">Fix → automated retest → verified only when the vulnerability no longer reports</p>
      </div>

      <Card title="Remediation queue">
        {remediation.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["Finding", "Severity", "Status", "Owner", "Due", "Retest", ""]}>
            {(remediation.data || []).map((r) => {
              const f = findingMap.get(r.finding_id);
              const rt = retestMap.get(r.finding_id);
              return (
                <tr key={r.id} className="hover:bg-ink-800/50">
                  <td className="max-w-md px-3 py-2">
                    <Link to={`/vulnerabilities/${r.finding_id}`} className="text-xs font-medium text-slate-200 hover:text-accent">{f?.title || r.finding_id.slice(0, 8)}</Link>
                  </td>
                  <td className="px-3 py-2">{f && <SeverityBadge severity={f.severity} />}</td>
                  <td className="px-3 py-2"><StatusBadge status={r.status} /></td>
                  <td className="px-3 py-2 text-xs text-slate-400">{r.owner || "—"}</td>
                  <td className="px-3 py-2 text-xs text-slate-500">{r.due_date || "—"}</td>
                  <td className="px-3 py-2">
                    {rt ? (
                      <Badge tone={rt.status === "PASSED" ? "green" : rt.status === "FAILED" ? "red" : "amber"}>{rt.status}</Badge>
                    ) : (
                      <span className="text-xs text-slate-600">pending</span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    {rt?.status !== "PASSED" && (
                      <button className="btn-ghost !py-0.5 text-[11px]" disabled={verify.isPending} onClick={() => verify.mutate(r.id)}>
                        Verify fix
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
        {remediation.data && !remediation.data.length && <Empty message="No remediation tasks — create one from a finding" />}
      </Card>

      <Card title="Retest history">
        <Table headers={["Retest", "Finding", "Status", "Before", "After", "When"]}>
          {(retests.data || []).map((r) => (
            <tr key={r.id} className="hover:bg-ink-800/50">
              <td className="mono px-3 py-2 text-xs text-slate-500">{r.id.slice(0, 8)}</td>
              <td className="px-3 py-2"><Link to={`/vulnerabilities/${r.finding_id}`} className="mono text-xs text-accent">{r.finding_id.slice(0, 8)}</Link></td>
              <td className="px-3 py-2">
                {r.status === "FAILED" ? <Badge tone="red">SECURITY REGRESSION DETECTED</Badge> : <StatusBadge status={r.status} />}
              </td>
              <td className="mono px-3 py-2 text-[10px] text-slate-500">{JSON.stringify(r.before_result)}</td>
              <td className="mono px-3 py-2 text-[10px] text-slate-500">{JSON.stringify(r.after_result)}</td>
              <td className="px-3 py-2 text-xs text-slate-500">{new Date(r.created_at).toLocaleString()}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
