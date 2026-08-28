import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, Card, Empty, Modal, SeverityBadge, Spinner, Table } from "../components/ui";

export default function Assets() {
  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const qc = useQueryClient();
  const assets = useQuery({
    queryKey: ["assets", search],
    queryFn: () => api.get<any[]>(`/api/assets?size=200${search ? `&search=${encodeURIComponent(search)}` : ""}`),
  });

  const create = useMutation({
    mutationFn: (body: any) => api.post("/api/assets", body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assets"] });
      setCreateOpen(false);
    },
  });

  const [form, setForm] = useState({ name: "", asset_type: "SERVER", ip_address: "", dns_name: "", exposure: "INTERNAL", criticality: "MEDIUM", environment: "production", owner: "" });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Asset Inventory</h1>
          <p className="text-sm text-slate-500">{assets.data?.length ?? "…"} assets · every entity feeds the attack graph</p>
        </div>
        <div className="flex gap-2">
          <input className="input w-64" placeholder="Search name / IP / DNS…" value={search} onChange={(e) => setSearch(e.target.value)} />
          <button className="btn-primary" onClick={() => setCreateOpen(true)}>+ Add asset</button>
        </div>
      </div>

      <Card>
        {assets.isLoading ? (
          <Spinner />
        ) : (
          <Table headers={["Asset", "Type", "IP / DNS", "Exposure", "Criticality", "Environment", "Last seen", ""]}>
            {(assets.data || []).map((a) => (
              <tr key={a.id} className="hover:bg-ink-800/50">
                <td className="px-3 py-2">
                  <Link to={`/assets/${a.id}`} className="font-medium text-accent hover:underline">{a.name}</Link>
                </td>
                <td className="px-3 py-2 text-xs text-slate-400">{a.asset_type}</td>
                <td className="px-3 py-2">
                  <span className="mono text-xs text-slate-300">{a.ip_address || "—"}</span>
                  {a.dns_name && <div className="mono text-[10px] text-slate-500">{a.dns_name}</div>}
                </td>
                <td className="px-3 py-2"><Badge tone={a.exposure === "INTERNET_FACING" ? "red" : a.exposure === "INTERNAL" ? "slate" : "amber"}>{a.exposure}</Badge></td>
                <td className="px-3 py-2"><SeverityBadge severity={a.criticality} /></td>
                <td className="px-3 py-2 text-xs text-slate-400">{a.environment}</td>
                <td className="px-3 py-2 text-xs text-slate-500">{a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}</td>
                <td className="px-3 py-2 text-right">
                  <Link to={`/assets/${a.id}`} className="text-xs text-accent">view →</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
        {assets.data && assets.data.length === 0 && <Empty message="No assets found" />}
      </Card>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="Register asset">
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="label">Name</label>
            <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <label className="label">Type</label>
            <select className="input" value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })}>
              {["HOST", "SERVER", "LAPTOP", "WORKSTATION", "NETWORK_DEVICE", "WEB_APPLICATION", "API", "DATABASE", "CONTAINER", "KUBERNETES_RESOURCE", "CLOUD_RESOURCE", "IDENTITY", "DOMAIN", "REPOSITORY", "SAAS_APPLICATION"].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Criticality</label>
            <select className="input" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="label">IP address</label>
            <input className="input" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
          </div>
          <div>
            <label className="label">DNS</label>
            <input className="input" value={form.dns_name} onChange={(e) => setForm({ ...form, dns_name: e.target.value })} />
          </div>
          <div>
            <label className="label">Exposure</label>
            <select className="input" value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
              {["INTERNET_FACING", "INTERNAL", "EXTERNAL", "UNKNOWN"].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="label">Environment</label>
            <input className="input" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} />
          </div>
          <div className="col-span-2">
            <label className="label">Owner</label>
            <input className="input" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          </div>
        </div>
        <button className="btn-primary mt-4" disabled={!form.name || create.isPending} onClick={() => create.mutate(form)}>
          Register asset
        </button>
      </Modal>
    </div>
  );
}
