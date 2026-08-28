import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { Badge, DemoTag } from "../components/ui";

const SUGGESTIONS = [
  "What are our most dangerous vulnerabilities?",
  "Which external asset changed today?",
  "Which vulnerabilities participate in a path to the database?",
  "Would our SOC detect this attack path?",
  "Show incidents related to this vulnerability.",
  "Which remediation gives us the biggest risk reduction?",
  "What changed after the recent deployment?",
  "Which security control is currently weakest?",
];

interface Msg {
  role: "user" | "assistant";
  text: string;
  citations: any[];
}

function citationLink(c: any): string | null {
  if (c.type === "finding") return `/vulnerabilities/${c.id}`;
  if (c.type === "incident") return `/incidents/${c.id}`;
  if (c.type === "asset") return `/assets/${c.id}`;
  if (c.type === "attack_path") return `/attack-paths`;
  return null;
}

export default function Copilot() {
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  const ask = useMutation({
    mutationFn: (q: string) => api.post<any>("/api/ai/copilot", { question: q }),
  });

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [msgs, ask.data]);

  const send = (q?: string) => {
    const question = (q ?? input).trim();
    if (!question || ask.isPending) return;
    setMsgs((m) => [...m, { role: "user", text: question, citations: [] }]);
    setInput("");
    ask.mutate(question, {
      onSuccess: (data) => {
        setMsgs((m) => [...m, { role: "assistant", text: data.answer, citations: data.citations || [] }]);
      },
      onError: (err) => {
        setMsgs((m) => [...m, { role: "assistant", text: `ERROR: ${err}`, citations: [] }]);
      },
    });
  };

  return (
    <div className="mx-auto flex h-full max-w-4xl flex-col">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">AI Security Copilot</h1>
          <p className="text-sm text-slate-500">Organization-aware answers retrieved from real platform data — with citations, never fabricated</p>
        </div>
        <DemoTag />
      </div>

      <div className="card flex-1 overflow-y-auto">
        <div className="space-y-3">
          {msgs.length === 0 && (
            <div>
              <p className="mb-2 text-sm text-slate-400">Ask about your actual security posture:</p>
              <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2">
                {SUGGESTIONS.map((s) => (
                  <button key={s} className="rounded border border-ink-700 bg-ink-800 px-2 py-1.5 text-left text-xs text-slate-300 hover:border-accent/40 hover:text-accent" onClick={() => send(s)}>
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}
          {msgs.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div className={`max-w-[85%] rounded-lg px-3 py-2 ${m.role === "user" ? "bg-accent text-ink-950" : "border border-ink-700 bg-ink-800"}`}>
                <div className={`whitespace-pre-wrap text-sm ${m.role === "user" ? "font-medium" : "text-slate-200"}`}>{m.text}</div>
                {m.citations.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5 border-t border-ink-600 pt-2">
                    {m.citations.map((c, j) => {
                      const to = citationLink(c);
                      const el = (
                        <span key={j} className="mono inline-flex items-center gap-1 rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-[10px] text-accent">
                          {c.type.toUpperCase()} · {c.id.slice(0, 10)}
                        </span>
                      );
                      return to ? <Link key={j} to={to}>{el}</Link> : el;
                    })}
                  </div>
                )}
              </div>
            </div>
          ))}
          {ask.isPending && <div className="flex items-center gap-2 text-sm text-slate-500"><span className="h-3 w-3 animate-spin rounded-full border-2 border-accent border-t-transparent" /> Retrieving from platform data…</div>}
          <div ref={bottomRef} />
        </div>
      </div>

      <div className="mt-3 flex gap-2">
        <input className="input" placeholder="Ask about your security data…" value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={(e) => e.key === "Enter" && send()} />
        <button className="btn-primary" onClick={() => send()} disabled={ask.isPending}>Ask</button>
      </div>
      <div className="mt-2 flex items-center gap-2 text-[10px] text-slate-600">
        <Badge tone="slate">provider: local-heuristic</Badge>
        <span>Copilot only answers from stored evidence. When evidence is missing it says INSUFFICIENT EVIDENCE.</span>
      </div>
    </div>
  );
}
