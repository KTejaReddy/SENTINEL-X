import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { api } from "../api/client";
import { useLiveStore } from "../store/live";
import { Badge, Card, DemoTag, Empty, Progress, SeverityBadge, Spinner, Stat, StatusBadge } from "../components/ui";

const SCENARIOS = [
  { id: "web_app_authorization", label: "Web App — Broken Object-Level Authorization" },
  { id: "api_authorization", label: "API — Broken Function-Level Authorization" },
  { id: "cloud_exposure", label: "Cloud — Public Storage Bucket" },
  { id: "secret_exposure", label: "Repo — Hardcoded Credential" },
  { id: "detection_gap", label: "Detection Gap — Undetected Lateral Movement" },
  { id: "security_regression", label: "Security Regression — Re-introduced Flaw" },
];

const STEPS = ["Engagement", "Recon", "Finding", "Validation", "Attack Path", "Blue Detection", "Incident", "Response", "Remediation", "Retest"];

export default function CommandCenter() {
  const qc = useQueryClient();
  const dash = useQuery({ queryKey: ["dashboard"], queryFn: () => api.get<any>("/api/command-center/data"), refetchInterval: 15000 });
  const live = useLiveStore((s) => s.events);
  const [scenario, setScenario] = useState("web_app_authorization");
  const [running, setRunning] = useState(false);
  const [jobIds, setJobIds] = useState<string[]>([]);
  const [exerciseNote, setExerciseNote] = useState("");

  const jobStatus = useQuery({
    queryKey: ["exercise-jobs", jobIds.join(",")],
    queryFn: async () => {
      const jobs = await api.get<any[]>("/api/jobs?size=50");
      return jobs.filter((j) => jobIds.includes(j.id));
    },
    enabled: jobIds.length > 0,
    refetchInterval: 2000,
  });

  const liveEvents = useMemo(
    () =>
      live
        .filter((e) => ["event_ingested", "detection", "job_completed", "job_failed", "notification", "job_queued", "job_started"].includes(e.type))
        .slice(0, 12),
    [live],
  );

  const runExercise = async () => {
    setRunning(true);
    setExerciseNote("");
    try {
      const res = await api.post("/api/ai/exercise", { scenario });
      setJobIds(res.jobs.map((j: any) => j.job_id));
      setExerciseNote(`${res.label} — engagement ${res.engagement_id.slice(0, 8)} queued.`);
      setTimeout(() => qc.invalidateQueries(), 1000);
    } catch (err) {
      setExerciseNote(String(err));
    } finally {
      setRunning(false);
    }
  };

  if (dash.isLoading) return <Spinner label="Loading command center…" />;
  if (dash.error) return <div className="text-critical">{String(dash.error)}</div>;
  const d = dash.data;
  const p = d.posture;

  const riskPie = [
    { name: "Critical", value: p.critical_findings, color: "#ef4444" },
    { name: "High", value: p.high_findings, color: "#f97316" },
    { name: "Other", value: Math.max(1, d.critical_findings.length ? d.critical_findings.length : 1), color: "#eab308" },
  ];

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">Command Center</h1>
          <p className="text-sm text-slate-500">Live security posture · continuous validation loop</p>
        </div>
        <div className="flex items-center gap-2">
          <DemoTag />
          <Badge tone={p.risk_level === "CRITICAL" ? "red" : p.risk_level === "HIGH" ? "amber" : "green"}>RISK: {p.risk_level}</Badge>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="Overall Risk" value={p.overall_risk} sub={p.risk_level} tone={p.risk_level === "CRITICAL" ? "critical" : p.risk_level === "HIGH" ? "high" : "low"} />
        <Stat label="Critical Findings" value={p.critical_findings} tone="critical" />
        <Stat label="High Findings" value={p.high_findings} tone="high" />
        <Stat label="Exposed Assets" value={p.exposed_assets} tone="accent" />
        <Stat label="Validated Vulns" value={p.validated_vulnerabilities} />
        <Stat label="Active Attack Paths" value={p.active_attack_paths} tone="high" />
        <Stat label="Open Incidents" value={p.open_incidents} tone="medium" />
        <Stat label="Detection Coverage" value={`${p.detection_coverage}%`} tone="low" />
        <Stat label="MTTD (min)" value={p.mttd_minutes ?? "—"} />
        <Stat label="MTTR (min)" value={p.mttr_minutes ?? "—"} />
        <Stat label="Security Regressions" value={p.security_regressions} tone={p.security_regressions > 0 ? "critical" : "low"} />
        <div className="card flex items-center justify-center">
          <ResponsiveContainer width="100%" height={80}>
            <PieChart>
              <Pie data={riskPie} dataKey="value" innerRadius={25} outerRadius={38} paddingAngle={2}>
                {riskPie.map((e, i) => (
                  <Cell key={i} fill={e.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Live Security Events" className="xl:col-span-2">
          <div className="max-h-64 space-y-1 overflow-y-auto">
            {liveEvents.length === 0 && <Empty message="Waiting for telemetry…" />}
            {liveEvents.map((e) => (
              <div key={e.id} className="flex items-center gap-2 rounded px-2 py-1 text-xs hover:bg-ink-800">
                <span className="mono w-28 shrink-0 text-slate-500">{new Date(e.ts).toLocaleTimeString()}</span>
                <Badge tone={e.type.includes("failed") ? "red" : e.type.includes("detection") ? "amber" : "blue"}>{e.type}</Badge>
                <span className="mono truncate text-slate-300">{JSON.stringify(e.payload).slice(0, 120)}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card title="Top Attack Paths">
          <div className="space-y-2">
            {d.top_attack_paths.map((p: any) => (
              <Link key={p.id} to="/attack-paths" className="block rounded border border-ink-700 bg-ink-800 p-2 hover:border-accent/40">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-slate-200">{p.name}</span>
                  <Badge tone={p.risk_score >= 75 ? "red" : p.risk_score >= 50 ? "amber" : "green"}>{p.risk_score}</Badge>
                </div>
                <Progress value={p.risk_score} tone={p.risk_score >= 75 ? "red" : "amber"} />
              </Link>
            ))}
            {d.top_attack_paths.length === 0 && <Empty message="No active attack paths" />}
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Card title="Live Incidents" right={<Link className="text-xs text-accent" to="/incidents">view all</Link>}>
          <div className="space-y-1.5">
            {d.live_incidents.map((i: any) => (
              <Link key={i.id} to={`/incidents/${i.id}`} className="flex items-center justify-between rounded border border-ink-700 bg-ink-800 px-2 py-1.5 hover:border-accent/40">
                <div className="min-w-0">
                  <div className="truncate text-xs text-slate-200">{i.title}</div>
                  <div className="mono text-[10px] text-slate-500">{i.id.slice(0, 8)} · {new Date(i.created_at).toLocaleString()}</div>
                </div>
                <div className="flex items-center gap-1.5">
                  <SeverityBadge severity={i.severity} />
                  <StatusBadge status={i.status} />
                </div>
              </Link>
            ))}
            {d.live_incidents.length === 0 && <Empty message="No open incidents" />}
          </div>
        </Card>

        <Card title="Critical Findings" right={<Link className="text-xs text-accent" to="/vulnerabilities">view all</Link>}>
          <div className="space-y-1.5">
            {d.critical_findings.map((f: any) => (
              <Link key={f.id} to={`/vulnerabilities/${f.id}`} className="block rounded border border-ink-700 bg-ink-800 px-2 py-1.5 hover:border-accent/40">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-xs text-slate-200">{f.title}</span>
                  <SeverityBadge severity={f.severity} />
                </div>
                <div className="mono text-[10px] text-slate-500">
                  CVSS {f.cvss ?? "n/a"} · {f.validated ? "VALIDATED" : "unvalidated"} · {f.status}
                </div>
              </Link>
            ))}
            {d.critical_findings.length === 0 && <Empty message="No critical findings" />}
          </div>
        </Card>

        <Card title="Detection Gaps">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs text-slate-400">
              {d.detection_gaps.deployed_rules} deployed · <span className="text-medium">{d.detection_gaps.draft_rules} draft proposals</span>
            </span>
            <Link className="text-xs text-accent" to="/purple">purple team</Link>
          </div>
          <div className="space-y-1">
            {d.detection_gaps.suggestions.map((r: any) => (
              <div key={r.rule_id} className="flex items-center justify-between rounded border border-ink-700 px-2 py-1 text-xs">
                <span className="mono truncate text-slate-300">{r.name}</span>
                <StatusBadge status={r.status} />
              </div>
            ))}
            {d.detection_gaps.suggestions.length === 0 && <Empty message="No detection proposals pending" />}
          </div>
          <div className="mt-3 border-t border-ink-700 pt-3">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Newly discovered assets</div>
            {d.new_assets.map((a: any) => (
              <Link key={a.id} to={`/assets/${a.id}`} className="flex items-center justify-between rounded px-1 py-0.5 text-xs hover:bg-ink-800">
                <span className="truncate text-slate-300">{a.name}</span>
                <span className="mono text-[10px] text-slate-500">{a.exposure}</span>
              </Link>
            ))}
          </div>
        </Card>
      </div>

      <Card
        title="Controlled Security Exercise"
        right={<DemoTag />}
      >
        <p className="mb-3 text-sm text-slate-400">
          Run a complete approved lab workflow through the real pipeline: engagement → recon → finding → validation → attack path → blue detection → incident → response → remediation → retest. All artifacts are labeled{" "}
          <span className="mono text-accent">CONTROLLED LAB</span>.
        </p>
        <div className="mb-3 grid grid-cols-1 gap-1.5 md:grid-cols-2 xl:grid-cols-3">
          {SCENARIOS.map((s) => (
            <button key={s.id} onClick={() => setScenario(s.id)} className={`rounded border px-3 py-2 text-left text-xs ${scenario === s.id ? "border-accent bg-accent/10 text-accent" : "border-ink-700 bg-ink-800 text-slate-300 hover:border-accent/40"}`}>
              {s.label}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-primary" onClick={runExercise} disabled={running}>
            {running ? "Starting…" : "▶ RUN CONTROLLED SECURITY EXERCISE"}
          </button>
          {exerciseNote && <span className="mono text-xs text-accent">{exerciseNote}</span>}
        </div>
        {jobStatus.data && jobStatus.data.length > 0 && (
          <div className="mt-4">
            <div className="mb-2 flex items-center gap-2">
              {STEPS.map((s, i) => (
                <span key={s} className="mono flex items-center gap-1 text-[10px] text-slate-500">
                  <span className={`flex h-4 w-4 items-center justify-center rounded-full ${jobStatus.data![0]?.status === "completed" ? "bg-low text-ink-950" : "bg-ink-700 text-slate-400"}`}>{jobStatus.data![0]?.status === "completed" ? "✓" : i + 1}</span>
                  {s}
                  {i < STEPS.length - 1 && <span className="text-ink-600">→</span>}
                </span>
              ))}
            </div>
            {jobStatus.data.map((j: any) => (
              <div key={j.id} className="mb-1 flex items-center gap-2 text-xs">
                <span className="mono w-24 text-slate-500">{j.kind}</span>
                <StatusBadge status={j.status} />
                <Progress value={j.progress} tone={j.status === "failed" ? "red" : "accent"} />
                {j.error && <span className="mono text-[10px] text-critical">{j.error}</span>}
              </div>
            ))}
            {jobStatus.data.every((j: any) => j.status === "completed") && (
              <div className="mt-2 flex gap-2">
                <button className="btn-ghost !py-1 text-xs" onClick={() => { qc.invalidateQueries(); setJobIds([]); }}>
                  Refresh posture
                </button>
                <Link to="/purple" className="btn-ghost !py-1 text-xs">Measure detection coverage →</Link>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
