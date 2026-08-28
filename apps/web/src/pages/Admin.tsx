import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner, StatusBadge, Table } from "../components/ui";

export default function Admin() {
  const [params] = useSearchParams();
  const tab = params.get("tab") || "system";
  const status = useQuery({ queryKey: ["system-status"], queryFn: () => api.get<any>("/api/system/status") });
  const users = useQuery({ queryKey: ["users"], queryFn: () => api.get<any[]>("/api/users") });
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => api.get<any[]>("/api/audit?size=100") });
  const agents = useQuery({ queryKey: ["agents"], queryFn: () => api.get<any[]>("/api/agents") });
  const notifications = useQuery({ queryKey: ["notifications"], queryFn: () => api.get<any[]>("/api/notifications"), refetchInterval: 15000 });

  const tabs = [
    ["system", "System Health"],
    ["users", "Users & Roles"],
    ["audit", "Audit Log"],
    ["agents", "AI Agents"],
    ["notifications", "Notifications"],
  ];

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold text-slate-100">Administration</h1>
        <p className="text-sm text-slate-500">Platform health · identities · audit trail · agent control plane</p>
      </div>

      <div className="flex flex-wrap gap-1">
        {tabs.map(([id, label]) => (
          <a key={id} href={`/admin?tab=${id}`} className={`tab ${tab === id ? "tab-active" : ""}`}>{label}</a>
        ))}
      </div>

      {tab === "system" && (
        <div className="space-y-4">
          <Card title="Platform version">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {status.data && (
                <>
                  <div><div className="text-[10px] uppercase text-slate-500">Version</div><div className="mono text-slate-200">{status.data.version}</div></div>
                  <div><div className="text-[10px] uppercase text-slate-500">Build</div><div className="mono text-slate-200">{status.data.build}</div></div>
                  <div><div className="text-[10px] uppercase text-slate-500">Git revision</div><div className="mono text-slate-200">{status.data.git_revision}</div></div>
                  <div><div className="text-[10px] uppercase text-slate-500">Environment</div><div className="mono text-slate-200">{status.data.environment}</div></div>
                </>
              )}
            </div>
          </Card>
          <Card title="Component health">
            {status.isLoading ? (
              <Spinner />
            ) : (
              <Table headers={["Component", "Status", "Detail"]}>
                {Object.entries(status.data?.components || {}).map(([k, v]: [string, any]) => (
                  <tr key={k} className="hover:bg-ink-800/50">
                    <td className="mono px-3 py-2 font-medium text-slate-200">{k}</td>
                    <td className="px-3 py-2"><Badge tone={v?.health === "OK" ? "green" : v?.health === "NOT_CONFIGURED" ? "slate" : v?.health === "NOT_INSTALLED" ? "amber" : "amber"}>{v?.health || "—"}</Badge></td>
                    <td className="mono px-3 py-2 text-[11px] text-slate-500">{v?.detail || v?.version || "—"}</td>
                  </tr>
                ))}
              </Table>
            )}
            <p className="mt-3 text-xs text-slate-500">
              Missing tools report <span className="mono text-amber">NOT_INSTALLED</span> and degrade gracefully. The lab-range adapter keeps the demo workflow functional without external binaries.
            </p>
          </Card>
        </div>
      )}

      {tab === "users" && (
        <Card title="Users & RBAC">
          <Table headers={["User", "Email", "Role", "Status", "MFA"]}>
            {(users.data || []).map((u) => (
              <tr key={u.id} className="hover:bg-ink-800/50">
                <td className="px-3 py-2 font-medium text-slate-200">{u.name}</td>
                <td className="mono px-3 py-2 text-xs text-slate-400">{u.email}</td>
                <td className="px-3 py-2"><Badge tone="blue">{u.role}</Badge></td>
                <td className="px-3 py-2"><StatusBadge status={u.status} /></td>
                <td className="px-3 py-2 text-xs">{u.mfa_enabled ? "✓" : "—"}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      {tab === "audit" && (
        <Card title="Audit log" right={<span className="mono text-[10px] text-slate-500">tamper-evident hash chain · tenant-isolated</span>}>
          <div className="max-h-[560px] overflow-y-auto">
            <Table headers={["When", "User", "Action", "Resource", "Outcome", "Detail"]}>
              {(audit.data || []).map((a) => (
                <tr key={a.id} className="hover:bg-ink-800/50">
                  <td className="mono px-3 py-1.5 text-[10px] text-slate-500">{new Date(a.created_at).toLocaleString()}</td>
                  <td className="mono px-3 py-1.5 text-[10px] text-slate-400">{a.user_id?.slice(0, 8) || "—"}</td>
                  <td className="mono px-3 py-1.5 text-[11px] text-slate-200">{a.action}</td>
                  <td className="mono px-3 py-1.5 text-[10px] text-slate-500">{a.resource_type} {a.resource_id?.slice(0, 8) || ""}</td>
                  <td className="px-3 py-1.5"><Badge tone={a.outcome === "success" ? "green" : "red"}>{a.outcome}</Badge></td>
                  <td className="mono max-w-xs truncate px-3 py-1.5 text-[10px] text-slate-500">{JSON.stringify(a.detail).slice(0, 80)}</td>
                </tr>
              ))}
            </Table>
          </div>
        </Card>
      )}

      {tab === "agents" && (
        <Card title="AI Agent Control Plane" right={<span className="mono text-[10px] text-slate-500">specialists · scoped · audited</span>}>
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {(agents.data || []).map((a) => (
              <div key={a.id} className="rounded border border-ink-700 bg-ink-800 p-3">
                <div className="flex items-center justify-between">
                  <span className="mono text-sm font-medium text-accent">{a.name}</span>
                  <Badge tone={a.enabled ? "green" : "red"}>{a.enabled ? "ENABLED" : "DISABLED"}</Badge>
                </div>
                <div className="mt-1 text-[10px] uppercase text-slate-500">{a.role} · {a.runs} runs</div>
                <div className="mono mt-2 flex flex-wrap gap-1 text-[9px] text-slate-500">
                  {(a.permissions || []).map((p: string) => <span key={p} className="rounded bg-ink-900 px-1 py-0.5">{p}</span>)}
                </div>
                <div className="mono mt-1 flex flex-wrap gap-1 text-[9px] text-slate-500">
                  {(a.tool_access || []).map((t: string) => <span key={t} className="rounded bg-ink-900 px-1 py-0.5 text-accent">{t}</span>)}
                </div>
              </div>
            ))}
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Agents request structured actions validated by the scope + policy engines. Every run is recorded with input/output/prompt version for audit.
          </p>
        </Card>
      )}

      {tab === "notifications" && (
        <Card title="Notifications">
          <div className="space-y-1">
            {(notifications.data || []).map((n) => (
              <div key={n.id} className={`flex items-start justify-between rounded border px-3 py-2 ${n.read ? "border-ink-700 opacity-60" : "border-accent/40 bg-accent/5"}`}>
                <div>
                  <div className="flex items-center gap-2">
                    <Badge tone="blue">{n.kind}</Badge>
                    <span className="text-xs font-medium text-slate-200">{n.title}</span>
                  </div>
                  {n.body && <div className="mt-0.5 text-[11px] text-slate-500">{n.body}</div>}
                </div>
                <span className="mono shrink-0 text-[10px] text-slate-600">{new Date(n.created_at).toLocaleString()}</span>
              </div>
            ))}
            {!notifications.data?.length && <Empty message="No notifications" />}
          </div>
        </Card>
      )}
    </div>
  );
}
