import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuthStore } from "../store/auth";

const DEMO_ACCOUNTS = [
  { email: "admin@acme.demo", role: "ORG_ADMIN" },
  { email: "ciso@acme.demo", role: "CISO" },
  { email: "pentester@acme.demo", role: "PENTESTER" },
  { email: "soc@acme.demo", role: "SOC_ANALYST" },
  { email: "engineer@acme.demo", role: "SECURITY_ENGINEER" },
  { email: "viewer@acme.demo", role: "VIEWER" },
];

export default function Login() {
  const [email, setEmail] = useState("admin@acme.demo");
  const [password, setPassword] = useState("SentinelX-2026!");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const setTokens = useAuthStore((s) => s.setTokens);
  const setUser = useAuthStore((s) => s.setUser);

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = await api.post("/api/auth/login", { email, password });
      setTokens(data.access_token, data.refresh_token);
      setUser(data.user);
      navigate("/");
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-ink-950">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <div className="mx-auto mb-3 flex h-14 w-14 items-center justify-center rounded-xl bg-accent text-2xl font-black text-ink-950">SX</div>
          <h1 className="text-2xl font-bold tracking-wide text-slate-100">SENTINEL X</h1>
          <p className="mt-1 text-sm text-slate-500">Continuously prove that your security controls work.</p>
          <div className="mt-3 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/5 px-3 py-1 text-[11px] text-accent">
            CONTROLLED LAB · DEMO ENVIRONMENT
          </div>
        </div>
        <form onSubmit={submit} className="card space-y-4">
          <div>
            <label className="label">Email</label>
            <input className="input" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
          </div>
          <div>
            <label className="label">Password</label>
            <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
          </div>
          {error && <div className="rounded border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</div>}
          <button className="btn-primary w-full justify-center" disabled={busy}>
            {busy ? "Authenticating…" : "Sign in"}
          </button>
        </form>
        <div className="card mt-4">
          <div className="label">Demo accounts (password: SentinelX-2026!)</div>
          <div className="grid grid-cols-2 gap-1.5">
            {DEMO_ACCOUNTS.map((a) => (
              <button key={a.email} className="rounded border border-ink-700 bg-ink-800 px-2 py-1.5 text-left text-[11px] hover:border-accent/50" onClick={() => { setEmail(a.email); setPassword("SentinelX-2026!"); }}>
                <div className="mono truncate text-slate-300">{a.email}</div>
                <div className="text-[10px] uppercase text-slate-500">{a.role}</div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
