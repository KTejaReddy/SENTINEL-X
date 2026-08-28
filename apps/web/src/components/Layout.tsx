import { ReactNode, useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useAuthStore } from "../store/auth";
import { useLiveStore } from "../store/live";
import { Badge } from "./ui";

const NAV = [
  { to: "/", label: "Command Center", icon: "◉" },
  { to: "/attack-surface", label: "Attack Surface", icon: "◧" },
  { to: "/assets", label: "Assets", icon: "▦" },
  { to: "/offensive", label: "Offensive", icon: "⚔" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "⚠" },
  { to: "/attack-paths", label: "Attack Paths", icon: "➹" },
  { to: "/soc", label: "SOC", icon: "▤" },
  { to: "/incidents", label: "Incidents", icon: "◆" },
  { to: "/hunting", label: "Threat Hunting", icon: "⌕" },
  { to: "/detection", label: "Detection", icon: "⛨" },
  { to: "/response", label: "Response", icon: "⟲" },
  { to: "/purple", label: "Purple Team", icon: "◐" },
  { to: "/remediation", label: "Remediation", icon: "✓" },
  { to: "/reports", label: "Reports", icon: "▤" },
  { to: "/copilot", label: "AI Copilot", icon: "✦" },
  { to: "/admin", label: "Administration", icon: "⚙" },
];

function CommandPalette({ onClose }: { onClose: () => void }) {
  const [q, setQ] = useState("");
  const navigate = useNavigate();
  const results = useQuery({
    queryKey: ["search", q],
    queryFn: () => api.get(`/api/search?q=${encodeURIComponent(q)}`),
    enabled: q.length >= 2,
  });
  const go = (to: string) => {
    navigate(to);
    onClose();
  };
  const groups: [string, any[]][] = [
    ["Assets", results.data?.assets || []],
    ["Findings", results.data?.findings || []],
    ["Incidents", results.data?.incidents || []],
    ["Engagements", results.data?.engagements || []],
  ];
  return (
    <div className="fixed inset-0 z-50 bg-black/60 pt-[15vh] backdrop-blur-sm" onClick={onClose}>
      <div className="card mx-auto w-full max-w-xl">
        <input autoFocus className="input" placeholder="Search assets, findings, incidents…  (Esc to close)" value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Escape" && onClose()} />
        <div className="mt-3 max-h-80 overflow-y-auto">
          {groups.map(([label, items]) =>
            items.length ? (
              <div key={label} className="mb-2">
                <div className="px-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
                {items.map((item, i) => (
                  <button key={i} className="block w-full rounded px-2 py-1.5 text-left text-sm text-slate-300 hover:bg-ink-700" onClick={() => go(navTarget(label, item))}>
                    {item.name || item.title} <span className="mono text-xs text-slate-500">{item.id.slice(0, 8)}</span>
                    {item.severity ? <Badge tone="amber">{item.severity}</Badge> : null}
                  </button>
                ))}
              </div>
            ) : null,
          )}
          {!q && (
            <div className="px-1 text-xs text-slate-500">
              <div className="mb-1 font-semibold uppercase tracking-wider">Quick navigation</div>
              {NAV.map((n) => (
                <button key={n.to} className="block w-full rounded px-2 py-1 text-left hover:bg-ink-700" onClick={() => go(n.to)}>
                  {n.icon} {n.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function navTarget(label: string, item: any) {
  if (label === "Assets") return `/assets/${item.id}`;
  if (label === "Findings") return `/vulnerabilities/${item.id}`;
  if (label === "Incidents") return `/incidents/${item.id}`;
  if (label === "Engagements") return `/offensive/${item.id}`;
  return "/";
}

export default function Layout() {
  const { user, logout } = useAuthStore();
  const live = useLiveStore((s) => s.events);
  const connected = useLiveStore((s) => s.connected);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const notifications = useQuery({
    queryKey: ["notifications"],
    queryFn: () => api.get<any[]>("/api/notifications"),
    refetchInterval: 20000,
  });
  const unread = notifications.data?.filter((n) => !n.read).length || 0;
  const recentLive = useMemo(() => live.slice(0, 8), [live]);

  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-ink-800 bg-ink-900">
        <div className="flex items-center gap-2 border-b border-ink-800 px-4 py-4">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-accent text-sm font-black text-ink-950">SX</div>
          <div>
            <div className="text-sm font-bold tracking-wide text-slate-100">SENTINEL X</div>
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Security Control Plane</div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto p-2">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                `mb-0.5 flex items-center gap-2 rounded-md px-3 py-1.5 text-[13px] font-medium ${isActive ? "bg-ink-700 text-accent" : "text-slate-400 hover:bg-ink-800 hover:text-slate-200"}`
              }
            >
              <span className="w-4 text-center">{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-ink-800 p-3">
          <div className="mb-2 flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${connected ? "bg-low" : "bg-critical"}`} />
            <span className="text-[11px] text-slate-500">{connected ? "REALTIME LIVE" : "REALTIME OFFLINE"}</span>
          </div>
          <button className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left hover:bg-ink-800" onClick={() => navigate("/admin")}>
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-ink-700 text-xs font-bold text-accent">
              {(user?.name || "U").slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="truncate text-xs font-medium text-slate-200">{user?.name}</div>
              <div className="mono truncate text-[10px] text-slate-500">{user?.role}</div>
            </div>
          </button>
          <button className="mt-1 w-full rounded px-2 py-1 text-left text-[11px] text-slate-500 hover:text-slate-300" onClick={() => { logout(); navigate("/login"); }}>
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-between border-b border-ink-800 bg-ink-900 px-4">
          <div className="flex items-center gap-3">
            <button className="btn-ghost !py-1 text-xs" onClick={() => setPaletteOpen(true)}>
              ⌘K Command palette
            </button>
            <Badge tone="blue">DEMO ENVIRONMENT</Badge>
          </div>
          <div className="flex items-center gap-3">
            {recentLive.slice(0, 4).map((e) => (
              <span key={e.id} className="mono hidden text-[10px] text-slate-500 lg:inline">
                {e.type}
              </span>
            ))}
            <div className="relative">
              <button className="relative rounded p-1.5 text-slate-400 hover:text-slate-200" onClick={() => navigate("/admin?tab=notifications")} title="Notifications">
                🔔
                {unread > 0 && <span className="absolute -right-0.5 -top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-critical text-[9px] font-bold text-white">{unread}</span>}
              </button>
            </div>
            <span className="mono text-[11px] text-slate-500">{user?.email}</span>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto p-5">
          <Outlet />
        </main>
      </div>

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </div>
  );
}
