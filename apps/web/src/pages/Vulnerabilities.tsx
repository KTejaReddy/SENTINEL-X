import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner, StatusBadge, Table } from "../components/ui";

export default function Vulnerabilities() {
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => api.get<any[]>("/api/findings?size=200"), refetchInterval: 10000 });

  const counts = (findings.data || []).reduce(
    (acc: Record<string, number>, f: any) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {},
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Vulnerability Management</h1>
          <p className="text-sm text-slate-500">Correlated findings · deduplicated across sources · validated evidence</p>
        </div>
        <div className="flex gap-2">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
            <Badge key={s} tone={s === "CRITICAL" ? "red" : s === "HIGH" ? "amber" : s === "MEDIUM" ? "amber" : "green"}>
              {s}: {counts[s] || 0}
            </Badge>
          ))}
        </div>
      </div>

      <Card>
        {findings.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["ID", "Finding", "Asset", "Severity", "CVSS", "CVE/CWE", "Status", "Validated", ""]}>
            {(findings.data || []).map((f) => (
              <tr key={f.id} className="hover:bg-ink-800/50">
                <td className="mono px-3 py-2 text-xs text-slate-500">{f.id.slice(0, 8)}</td>
                <td className="max-w-md px-3 py-2">
                  <Link to={`/vulnerabilities/${f.id}`} className="font-medium text-slate-200 hover:text-accent">{f.title}</Link>
                  {f.endpoint && <div className="mono truncate text-[10px] text-slate-500">{f.endpoint}</div>}
                </td>
                <td className="px-3 py-2 text-xs text-slate-400">{f.asset_id?.slice(0, 8) || "—"}</td>
                <td className="px-3 py-2"><SeverityBadge severity={f.severity} /></td>
                <td className="mono px-3 py-2 text-xs text-slate-300">{f.cvss ?? "—"}</td>
                <td className="mono px-3 py-2 text-xs text-slate-500">{f.cve || f.cwe || "—"}</td>
                <td className="px-3 py-2"><StatusBadge status={f.status} /></td>
                <td className="px-3 py-2 text-xs">{f.validated ? <span className="text-low">✓</span> : <span className="text-slate-600">—</span>}</td>
                <td className="px-3 py-2 text-right">
                  <Link to={`/vulnerabilities/${f.id}`} className="text-xs text-accent">view →</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
        {findings.data && !findings.data.length && <Empty message="No findings yet" />}
      </Card>
    </div>
  );
}
