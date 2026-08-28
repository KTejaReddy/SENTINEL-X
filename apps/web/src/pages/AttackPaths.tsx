import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ReactFlow, Background, Controls, Handle, MarkerType, Position } from "@xyflow/react";
import type { NodeMouseHandler } from "@xyflow/react";
import { api } from "../api/client";
import { Badge, Card, Empty, SeverityBadge, Spinner } from "../components/ui";

const TYPE_STYLE: Record<string, string> = {
  WEB_APPLICATION: "#38bdf8",
  API: "#818cf8",
  DATABASE: "#f472b6",
  SERVER: "#94a3b8",
  NETWORK_DEVICE: "#f59e0b",
  CONTAINER: "#2dd4bf",
  KUBERNETES_RESOURCE: "#a78bfa",
  CLOUD_RESOURCE: "#60a5fa",
  IDENTITY: "#34d399",
  WORKSTATION: "#64748b",
  LAPTOP: "#64748b",
  DOMAIN: "#f87171",
  REPOSITORY: "#4ade80",
  SAAS_APPLICATION: "#c084fc",
};

const EDGE_STYLE: Record<string, string> = {
  ATTACK_PATH: "#ef4444",
  VULNERABILITY: "#f97316",
  DATA_FLOW: "#38bdf8",
  TRUST: "#a78bfa",
  CAN_ACCESS: "#64748b",
  DEPENDS_ON: "#64748b",
  NETWORK_ACCESS: "#64748b",
};

function GraphNode({ data }: { data: any }) {
  return (
    <>
      <Handle type="target" position={Position.Top} />
      <div className={`rounded-md border-2 px-3 py-1.5 text-xs font-semibold ${data.highlight ? "border-critical bg-critical/10 text-critical shadow-glow" : "border-ink-600 bg-ink-800 text-slate-200"}`} style={{ borderColor: data.color }}>
        <div className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-full" style={{ background: data.color }} />
          {data.label}
        </div>
        <div className="mono text-[9px] font-normal text-slate-500">
          {data.type} · {data.criticality}
          {data.finding_count ? ` · ${data.finding_count} findings` : ""}
          {data.incident ? " · ⚠ incident" : ""}
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} />
    </>
  );
}

const nodeTypes = { sentinel: GraphNode };

export default function AttackPaths() {
  const qc = useQueryClient();
  const paths = useQuery({ queryKey: ["attack-paths"], queryFn: () => api.get<any[]>("/api/attack-paths"), refetchInterval: 10000 });
  const graph = useQuery({ queryKey: ["attack-graph"], queryFn: () => api.get<any>("/api/attack-graph"), refetchInterval: 15000 });
  const [selected, setSelected] = useState<any>(null);
  const [pathHighlight, setPathHighlight] = useState<string | null>(null);

  const { nodes, edges } = useMemo(() => {
    const g = graph.data || { nodes: [], edges: [] };
    const highlighted = new Set<string>();
    if (pathHighlight && paths.data) {
      const p = paths.data.find((x: any) => x.id === pathHighlight);
      p?.nodes.forEach((n: any) => n.asset_id && highlighted.add(n.asset_id));
    }
    const nodes = g.nodes.map((n: any) => ({
      id: n.id,
      position: { x: (Math.abs(hash(n.id)) % 12) * 120, y: (Math.abs(hash(n.id + "y")) % 8) * 100 },
      data: { ...n, color: TYPE_STYLE[n.type] || "#94a3b8", highlight: highlighted.has(n.id) },
      type: "sentinel",
    }));
    const edges = g.edges.map((e: any, i: number) => ({
      id: e.id || `e${i}`,
      source: e.source,
      target: e.target,
      style: { stroke: EDGE_STYLE[e.type] || "#475569", strokeWidth: e.type === "ATTACK_PATH" ? 3 : 1.5, strokeDasharray: e.type === "ATTACK_PATH" ? "6 3" : undefined },
      markerEnd: { type: MarkerType.ArrowClosed, color: EDGE_STYLE[e.type] || "#475569" },
      label: e.type === "ATTACK_PATH" ? "ATTACK PATH" : e.type,
      labelStyle: { fontSize: 8, fill: "#64748b" },
    }));
    return { nodes, edges };
  }, [graph.data, paths.data, pathHighlight]);

  const recompute = async () => {
    await api.post("/api/attack-paths/compute", {});
    qc.invalidateQueries({ queryKey: ["attack-paths"] });
    qc.invalidateQueries({ queryKey: ["attack-graph"] });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Attack Paths</h1>
          <p className="text-sm text-slate-500">Directed graph from entry points to high-value destinations — computed from live data</p>
        </div>
        <button className="btn-primary" onClick={recompute}>Recompute paths</button>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Active Paths" className="xl:col-span-1">
          <div className="space-y-2">
            {paths.isLoading && <Spinner />}
            {(paths.data || []).map((p) => (
              <button key={p.id} onClick={() => setPathHighlight(p.id === pathHighlight ? null : p.id)} className={`block w-full rounded border p-2 text-left hover:bg-ink-800 ${pathHighlight === p.id ? "border-critical bg-critical/5" : "border-ink-700"}`}>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-200">{p.name}</span>
                  <Badge tone={p.risk_score >= 75 ? "red" : p.risk_score >= 50 ? "amber" : "green"}>{p.risk_score}</Badge>
                </div>
                <div className="mono mt-1 flex flex-wrap items-center gap-1 text-[10px] text-slate-500">
                  {p.nodes.sort((a: any, b: any) => a.ordinal - b.ordinal).map((n: any, i: number, arr: any[]) => (
                    <span key={n.id}>
                      {n.label}
                      {i < arr.length - 1 && <span className="text-critical"> → </span>}
                    </span>
                  ))}
                </div>
              </button>
            ))}
            {paths.data && !paths.data.length && <Empty message="No active attack paths — recompute after findings exist" />}
          </div>
        </Card>

        <div className="card xl:col-span-2" style={{ height: "560px" }}>
          {graph.isLoading ? (
            <Spinner />
          ) : (
            <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView onNodeClick={((_: any, n: any) => {
              const node = graph.data?.nodes.find((x: any) => x.id === n.id);
              setSelected(node);
            }) as NodeMouseHandler} minZoom={0.2}>
              <Background color="#1b2230" gap={24} />
              <Controls />
            </ReactFlow>
          )}
          <div className="mt-2 flex flex-wrap gap-2 text-[10px] text-slate-500">
            {Object.entries(EDGE_STYLE).map(([k, v]) => (
              <span key={k} className="flex items-center gap-1"><span className="h-0.5 w-4 rounded" style={{ background: v }} /> {k}</span>
            ))}
            <span className="ml-2">Click a node for context · click a path to highlight</span>
          </div>
        </div>
      </div>

      {selected && (
        <Card title={`${selected.label} — security context`} right={<button className="text-xs text-slate-500" onClick={() => setSelected(null)}>close ✕</button>}>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <div><div className="text-[10px] uppercase text-slate-500">Type</div><div className="text-sm text-slate-200">{selected.type}</div></div>
            <div><div className="text-[10px] uppercase text-slate-500">Criticality</div><SeverityBadge severity={selected.criticality} /></div>
            <div><div className="text-[10px] uppercase text-slate-500">Exposure</div><Badge tone={selected.exposure === "INTERNET_FACING" ? "red" : "slate"}>{selected.exposure}</Badge></div>
            <div><div className="text-[10px] uppercase text-slate-500">Findings</div><div className="text-sm text-slate-200">{selected.finding_count} ({selected.critical_findings} critical/high)</div></div>
          </div>
          <div className="mt-3 flex gap-2">
            <Link to={`/assets/${selected.id}`} className="btn-ghost !py-1 text-xs">Open asset</Link>
            <Link to={`/vulnerabilities?asset=${selected.id}`} className="btn-ghost !py-1 text-xs">Findings</Link>
          </div>
        </Card>
      )}
    </div>
  );
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
