import { useEffect, useMemo, useState } from "react";
import { api, type AuditRow } from "../api";
import type { Run } from "../App";

/** Every use of a secret that skipped the identity check: by access key, or approved by you. */
export default function ActivityView({ run, version }: { run: Run; version: number }) {
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  useEffect(() => {
    run(() => api.audit(2000)).then((r) => setRows(r ?? []));
  }, [run]);
  // New entries written outside the window (an agent's use) appear without a restart.
  useEffect(() => {
    if (version > 0) api.audit(2000).then(setRows).catch(() => {});
  }, [version]);

  return (
    <main className="page wide">
      <h1>Activity</h1>
      <p className="muted">Every time an agent or tool used a secret without asking you (through its access key) or with your approval.</p>
      {rows && rows.length > 0 && <Metrics rows={rows} />}
      {rows === null ? null : rows.length === 0 ? (
        <div className="card"><p className="muted">Nothing yet.</p></div>
      ) : (
        <div className="card table-card">
          <table className="table">
            <thead>
              <tr><th>When</th><th>Who</th><th>Did</th><th>Secrets</th><th>Allowed by</th><th>Started from</th></tr>
            </thead>
            <tbody>
              {rows.slice(0, 500).map((r, i) => (
                <tr key={i}>
                  <td className="nowrap">{new Date(r.time).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}</td>
                  <td>{r.key ?? "A tool"}</td>
                  <td>{r.operation}</td>
                  <td>{r.secrets.join(", ")}</td>
                  <td>{r.via}</td>
                  <td className="muted small-text" title={r.chain.join(" ← ")}>{r.chain.slice(0, 3).join(" ← ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}

const DAYS = 30;

/** Cards over the table: uses in the last 30 days, and the secrets used most. */
function Metrics({ rows }: { rows: AuditRow[] }) {
  const m = useMemo(() => {
    const since = Date.now() - DAYS * 86_400_000;
    const recent = rows.filter((r) => new Date(r.time).getTime() >= since);
    const bySecret = new Map<string, { uses: number; last: number; who: Map<string, number> }>();
    const tools = new Set<string>();
    for (const r of recent) {
      const who = r.key ?? "A tool";
      tools.add(who);
      const t = new Date(r.time).getTime();
      for (const name of new Set(r.secrets)) {
        const e = bySecret.get(name) ?? { uses: 0, last: 0, who: new Map() };
        e.uses++;
        e.last = Math.max(e.last, t);
        e.who.set(who, (e.who.get(who) ?? 0) + 1);
        bySecret.set(name, e);
      }
    }
    const top = [...bySecret.entries()]
      .sort((a, b) => b[1].uses - a[1].uses || b[1].last - a[1].last)
      .slice(0, 4)
      .map(([name, e]) => ({ name, uses: e.uses, last: e.last, who: [...e.who.entries()].sort((a, b) => b[1] - a[1])[0][0] }));
    return { uses: recent.length, secrets: bySecret.size, tools: tools.size, top };
  }, [rows]);

  const max = m.top[0]?.uses ?? 1;
  return (
    <div className="metrics">
      <div className="card metric">
        <div className="metric-label">Uses · last {DAYS} days</div>
        <div className="metric-value">{m.uses}</div>
        <div className="muted small-text">{plural(m.secrets, "secret")} · {plural(m.tools, "key or tool", "keys or tools")}</div>
      </div>
      {m.top.map((t, i) => (
        <div className="card metric" key={t.name}>
          <div className="metric-label">#{i + 1} most used</div>
          <div className="metric-name" title={t.name}>{t.name}</div>
          <div className="metric-bar"><span style={{ width: `${Math.max(4, (t.uses / max) * 100)}%` }} /></div>
          <div className="muted small-text">{plural(t.uses, "use")} · mostly {t.who} · {ago(t.last)}</div>
        </div>
      ))}
      {m.top.length === 0 && (
        <div className="card metric"><div className="metric-label">Most used</div><p className="muted small-text">Nothing in the last {DAYS} days.</p></div>
      )}
    </div>
  );
}

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

function ago(t: number) {
  const min = Math.round((Date.now() - t) / 60_000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(h / 24);
  return d === 1 ? "yesterday" : `${d} days ago`;
}
