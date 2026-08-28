import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, DemoTag, Empty, Modal, Spinner } from "../components/ui";

export default function Evidence() {
  const evidence = useQuery({ queryKey: ["evidence"], queryFn: () => api.get<any[]>("/api/evidence?limit=200") });
  const [open, setOpen] = useState<any>(null);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Evidence Vault</h1>
          <p className="text-sm text-slate-500">Content-addressed · immutable · tenant-isolated</p>
        </div>
        <DemoTag />
      </div>

      <Card>
        {evidence.isLoading ? (
          <Spinner />
        ) : (
          <div className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            {(evidence.data || []).map((e) => (
              <button key={e.id} className="rounded border border-ink-700 bg-ink-800 p-3 text-left hover:border-accent/40" onClick={() => setOpen(e)}>
                <div className="mb-1 flex items-center justify-between">
                  <Badge tone="blue">{e.kind}</Badge>
                  {e.demo && <Badge tone="blue">LAB</Badge>}
                </div>
                <div className="mono text-[10px] text-slate-500">sha256 {e.content_hash.slice(0, 16)}…</div>
                <div className="mono mt-1 text-[11px] text-slate-400">{e.tool} · {new Date(e.captured_at || e.created_at).toLocaleString()}</div>
                <div className="mt-1 line-clamp-3 text-[11px] text-slate-300">{JSON.stringify(e.data).slice(0, 180)}</div>
              </button>
            ))}
          </div>
        )}
        {evidence.data && !evidence.data.length && <Empty message="No evidence stored" />}
      </Card>

      <Modal open={!!open} onClose={() => setOpen(null)} title="Evidence detail" wide>
        {open && (
          <div>
            <div className="mb-2 flex gap-2">
              <Badge tone="blue">{open.kind}</Badge>
              <span className="mono text-xs text-slate-400">{open.tool}</span>
              <span className="mono text-[10px] text-slate-500">sha256 {open.content_hash}</span>
            </div>
            <pre className="mono max-h-96 overflow-auto rounded bg-ink-900 p-3 text-[11px] text-slate-300">{JSON.stringify(open.data, null, 2)}</pre>
          </div>
        )}
      </Modal>
    </div>
  );
}
