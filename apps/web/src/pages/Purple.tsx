import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import { Badge, Card, DemoTag, Empty, Progress, Spinner, StatusBadge } from "../components/ui";

const SCENARIOS = [
  { id: "web_app_authorization", label: "Web App Authorization" },
  { id: "api_authorization", label: "API Authorization" },
  { id: "cloud_exposure", label: "Cloud Exposure" },
  { id: "secret_exposure", label: "Secret Exposure" },
  { id: "detection_gap", label: "Detection Gap" },
  { id: "security_regression", label: "Security Regression" },
];

export default function Purple() {
  const qc = useQueryClient();
  const summary = useQuery({ queryKey: ["purple"], queryFn: () => api.get<any>("/api/purple/coverage") });
  const jobs = useQuery({ queryKey: ["purple-jobs"], queryFn: () => api.get<any[]>("/api/jobs?size=50"), refetchInterval: 4000 });
  const engagements = useQuery({ queryKey: ["engagements"], queryFn: () => api.get<any[]>("/api/engagements") });
  const [scenario, setScenario] = useState("web_app_authorization");
  const [gapDetail, setGapDetail] = useState<any>(null);

  const run = useMutation({
    mutationFn: async () => {
      const eng = (engagements.data || []).find((e: any) => e.status === "APPROVED" || e.status === "RUNNING");
      if (!eng) throw new Error("No approved engagement available");
      await api.post("/api/purple/exercise", { engagement_id: eng.id, scenario });
      setTimeout(() => qc.invalidateQueries(), 500);
    },
  });

  const exerciseJobs = (jobs.data || []).filter((j: any) => j.kind === "purple" && j.status === "completed");

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Purple Team</h1>
          <p className="text-sm text-slate-500">Red action → expected telemetry → actual telemetry → detection? → response? → control score</p>
        </div>
        <DemoTag />
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Exercises</div><div className="text-2xl font-bold">{exerciseJobs.length}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Deployed rules</div><div className="text-2xl font-bold text-low">{summary.data?.detection_rules_deployed ?? "…"}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Draft proposals</div><div className="text-2xl font-bold text-medium">{summary.data?.detection_rules_draft ?? "…"}</div></div>
        <div className="card"><div className="text-[11px] uppercase text-slate-500">Control gaps</div><div className="text-2xl font-bold text-high">{summary.data?.detection_rules_draft ?? "…"}</div></div>
      </div>

      <Card title="Run purple exercise">
        <div className="mb-3 grid grid-cols-2 gap-1.5 md:grid-cols-3">
          {SCENARIOS.map((s) => (
            <button key={s.id} onClick={() => setScenario(s.id)} className={`rounded border px-2 py-1.5 text-left text-xs ${scenario === s.id ? "border-accent bg-accent/10 text-accent" : "border-ink-700 bg-ink-800 text-slate-300 hover:border-accent/40"}`}>
              {s.label}
            </button>
          ))}
        </div>
        <button className="btn-primary" onClick={() => run.mutate()} disabled={run.isPending}>
          ▶ Measure detection coverage
        </button>
        {run.isError && <div className="mt-2 text-xs text-critical">{String(run.error)}</div>}
      </Card>

      <Card title="Coverage results">
        <div className="space-y-3">
          {exerciseJobs.slice(0, 6).map((j) => {
            const r = j.result || {};
            const stages: any[] = r.stages || [];
            return (
              <div key={j.id} className="rounded border border-ink-700 bg-ink-800 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge tone="blue">{r.meta?.scenario || (j.params || {}).scenario || "scenario"}</Badge>
                    <span className="mono text-[10px] text-slate-500">job {j.id.slice(0, 8)} · {new Date(j.finished_at).toLocaleString()}</span>
                  </div>
                  <Badge tone={r.coverage?.coverage_pct >= 60 ? "green" : r.coverage?.coverage_pct >= 30 ? "amber" : "red"}>
                    COVERAGE {r.coverage?.coverage_pct ?? 0}%
                  </Badge>
                </div>
                {stages.length > 0 ? (
                  <div className="grid grid-cols-2 gap-1.5 md:grid-cols-3">
                    {stages.map((s) => (
                      <button key={s.stage} className={`rounded border px-2 py-1.5 text-left text-[11px] ${s.covered ? "border-low/40 bg-low/5" : "border-critical/40 bg-critical/5"}`} onClick={() => setGapDetail(s)}>
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-slate-200">{s.stage}</span>
                          <span className={s.covered ? "text-low" : "text-critical"}>{s.covered ? "✓" : "✗"}</span>
                        </div>
                        <div className="mono text-[9px] text-slate-500">{s.technique || ""}</div>
                        <div className="mt-0.5 text-[9px] text-slate-400">
                          telemetry: {s.has_telemetry ? "yes" : "no"} · detected: {s.detected ? "yes" : "no"}
                          {s.matched_rule ? ` · ${s.matched_rule}` : ""}
                        </div>
                      </button>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-slate-500">Completed job — coverage computed by stage. Open the engagement to see live progress.</div>
                )}
                {(r.gaps || []).length > 0 && (
                  <div className="mt-2 rounded border border-amber/30 bg-amber/5 p-2">
                    <div className="mb-1 text-[10px] font-bold uppercase text-amber">Detection gaps → proposals created as DRAFT rules</div>
                    {(r.gaps || []).map((g: any, i: number) => (
                      <div key={i} className="text-[11px] text-slate-300">• {g.stage}: {g.recommended_detection}</div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          {!exerciseJobs.length && <Empty message="Run an exercise to measure detection coverage per attack stage." />}
        </div>
      </Card>

      {gapDetail && (
        <Card title={`Gap detail — ${gapDetail.stage}`} right={<button className="text-xs text-slate-500" onClick={() => setGapDetail(null)}>close ✕</button>}>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div>
              <div className="label">Evidence observed</div>
              <div className="mono text-xs text-slate-300">{(gapDetail.observed_telemetry || []).join(", ") || "none"}</div>
            </div>
            <div>
              <div className="label">Expected telemetry</div>
              <div className="mono text-xs text-slate-300">{(gapDetail.expected_telemetry || []).join(", ")}</div>
            </div>
            <div>
              <div className="label">Missing telemetry</div>
              <div className="text-xs text-amber">{(gapDetail.missing_telemetry || []).join(", ") || "detection gap (no rule matched)"}</div>
            </div>
            <div>
              <div className="label">Recommended detection</div>
              <div className="text-xs text-accent">{gapDetail.recommended_detection || "propose a rule for this stage"}</div>
            </div>
          </div>
          <div className="mt-3 text-[11px] text-slate-500">
            Recommendations are created as <span className="mono">DRAFT</span> detection rules on the Detection page — deploy after testing. Deployed rules become regression tests.
          </div>
        </Card>
      )}
    </div>
  );
}
