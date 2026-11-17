import { useEffect, useState } from "react";
import { api, type AuditRow } from "../api";
import type { Run } from "../App";

/** Every use of a secret that skipped the identity check: by access key, or approved by you. */
export default function ActivityView({ run, version }: { run: Run; version: number }) {
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  useEffect(() => {
    run(() => api.audit(500)).then((r) => setRows(r ?? []));
  }, [run]);
  // New entries written outside the window (an agent's use) appear without a restart.
  useEffect(() => {
    if (version > 0) api.audit(500).then(setRows).catch(() => {});
  }, [version]);

  return (
    <main className="page">
      <h1>Activity</h1>
      <p className="muted">Every time an agent or tool used a secret without asking you (through its access key) or with your approval.</p>
      {rows === null ? null : rows.length === 0 ? (
        <div className="card"><p className="muted">Nothing yet.</p></div>
      ) : (
        <div className="card table-card">
          <table className="table">
            <thead>
              <tr><th>When</th><th>Who</th><th>Did</th><th>Secrets</th><th>Allowed by</th><th>Started from</th></tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
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
