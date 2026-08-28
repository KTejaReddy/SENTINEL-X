import { ReactNode } from "react";

export const sevColor: Record<string, string> = {
  CRITICAL: "text-critical border-critical/40 bg-critical/10",
  HIGH: "text-high border-high/40 bg-high/10",
  MEDIUM: "text-medium border-medium/40 bg-medium/10",
  LOW: "text-low border-low/40 bg-low/10",
  INFO: "text-info border-info/40 bg-info/10",
};

export const sevBg: Record<string, string> = {
  CRITICAL: "bg-critical",
  HIGH: "bg-high",
  MEDIUM: "bg-medium",
  LOW: "bg-low",
  INFO: "bg-info",
};

export function Badge({ children, tone = "slate" }: { children: ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    slate: "bg-ink-700 text-slate-300 border-ink-600",
    accent: "bg-accent/10 text-accent border-accent/40",
    green: "bg-low/10 text-low border-low/40",
    red: "bg-critical/10 text-critical border-critical/40",
    amber: "bg-medium/10 text-medium border-medium/40",
    blue: "bg-contained/10 text-contained border-contained/40",
  };
  return (
    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-semibold ${tones[tone] || tones.slate}`}>
      {children}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "INFO").toUpperCase();
  return <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[11px] font-bold ${sevColor[s] || sevColor.INFO}`}>{s}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  const lower = (status || "").toLowerCase();
  const tone = ["closed", "verified", "fixed", "resolved", "passed", "completed", "executed", "contained", "healthy", "remediated", "allowed", "approved"].some((k) => lower.includes(k))
    ? "green"
    : ["open", "investigating", "running", "queued", "pending", "pending_approval", "validating", "retesting", "remediation", "medium"].some((k) => lower.includes(k))
      ? "amber"
      : lower.includes("critical") || lower.includes("failed") || lower.includes("denied") || lower.includes("rejected") || lower.includes("cancelled") || lower.includes("gap") || lower.includes("blocked") || lower.includes("high")
        ? "red"
        : lower.includes("draft") || lower.includes("lab") || lower.includes("demo")
          ? "blue"
          : "slate";
  return <Badge tone={tone}>{status}</Badge>;
}

export function Card({ title, children, right, className = "" }: { title?: ReactNode; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <div className={`card ${className}`}>
      {(title || right) && (
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">{title}</h3>
          {right}
        </div>
      )}
      {children}
    </div>
  );
}

export function Stat({ label, value, sub, tone = "default" }: { label: string; value: ReactNode; sub?: ReactNode; tone?: string }) {
  const tones: Record<string, string> = {
    default: "text-slate-100",
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
    accent: "text-accent",
  };
  return (
    <div className="card flex flex-col justify-between">
      <div className="text-[11px] font-medium uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${tones[tone]}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-ink-700 text-[11px] uppercase tracking-wider text-slate-500">
            {headers.map((h) => (
              <th key={h} className="px-3 py-2 font-semibold">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-800">{children}</tbody>
      </table>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-slate-400">
      <div className="h-4 w-4 animate-spin rounded-full border-2 border-accent border-t-transparent" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  );
}

export function Empty({ message }: { message: string }) {
  return <div className="py-10 text-center text-sm text-slate-500">{message}</div>;
}

export function DemoTag() {
  return <Badge tone="blue">DEMO DATA · CONTROLLED LAB</Badge>;
}

export function ErrorBox({ error }: { error: unknown }) {
  return <div className="rounded-md border border-critical/40 bg-critical/10 px-3 py-2 text-sm text-critical">{String(error)}</div>;
}

export function Progress({ value, tone = "accent" }: { value: number; tone?: string }) {
  const colors: Record<string, string> = {
    accent: "bg-accent",
    green: "bg-low",
    red: "bg-critical",
    amber: "bg-medium",
  };
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-ink-700">
      <div className={`h-full ${colors[tone]}`} style={{ width: `${Math.min(100, Math.max(0, value))}%`, transition: "width 0.5s" }} />
    </div>
  );
}

export function Modal({ open, onClose, title, children, wide = false }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-20 backdrop-blur-sm" onClick={onClose}>
      <div className={`card w-full ${wide ? "max-w-3xl" : "max-w-lg"}`} onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-200">{title}</h3>
          <button className="text-slate-400 hover:text-slate-200" onClick={onClose}>
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
