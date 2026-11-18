import { useEffect, useState } from "react";
import { AlertTriangle, FileUp, KeyRound } from "lucide-react";
import { api, type CategorySummary, type PasswordImport } from "../api";
import CategoryDropdown from "./CategoryDropdown";
import type { Run } from "../App";
import { Modal, useToast } from "./ui";

/**
 * Import another password manager's CSV export (Chrome, Edge, Firefox, Bitwarden, 1Password,
 * LastPass, KeePassXC, Apple Passwords): a preview of every login it holds, then the import. The
 * preview never includes passwords.
 */
export default function PasswordImportDialog({ initialPath, categories, run, onClose, onImported }: {
  initialPath: string | null;
  categories: CategorySummary[];
  run: Run;
  onClose: () => void;
  onImported: () => void;
}) {
  const toast = useToast();
  const [path, setPath] = useState<string | null>(initialPath);
  const [category, setCategory] = useState("");
  const [overwrite, setOverwrite] = useState(false);
  const [deleteFile, setDeleteFile] = useState(true);
  const [plan, setPlan] = useState<PasswordImport | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!path) return setPlan(null);
    let current = true;
    run(() => api.passwordImportPlan(path, category.trim() || null)).then((p) => current && p && setPlan(p));
    return () => { current = false; };
  }, [path, category, run]);

  const pick = async () => {
    const p = await run(() => api.pickPasswordExport());
    if (p) setPath(p);
  };

  const items = plan?.items ?? [];
  const existing = items.filter((i) => i.exists).length;
  const count = overwrite ? items.length : items.length - existing;

  const start = async () => {
    if (!path) return;
    setBusy(true);
    const r = await run(() => api.passwordImport(path, category.trim() || null, overwrite, deleteFile));
    setBusy(false);
    if (r) {
      const skipped = r.items.length - r.imported + r.skipped.length;
      toast(`Imported ${r.imported === 1 ? "1 login" : `${r.imported} logins`}${skipped ? `, skipped ${skipped}` : ""}.${deleteFile && r.imported ? " The export file was deleted." : ""}`);
      onImported();
      onClose();
    }
  };

  return (
    <Modal title="Import from another password manager" onClose={onClose} wide
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={!plan || busy || count === 0} onClick={start}>
          {busy ? "Importing…" : count === 1 ? "Import 1 login" : `Import ${count} logins`}
        </button>
      </>}>
      <p className="muted">
        Export your passwords as CSV from Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass, KeePassXC or Apple Passwords,
        then choose the file. Logins keep their website, username, notes and one-time codes; folders become categories.
      </p>
      <div className="import-pick">
        <button className="button" onClick={pick}><FileUp size={15} /> {path ? "Choose another file…" : "Choose the export…"}</button>
        {path && <span className="mono small-text" title={path}>{path}</span>}
      </div>

      {plan && (
        <>
          <p><strong>{plan.format}</strong> export: {items.length === 1 ? "1 login" : `${items.length} logins`}
            {existing > 0 && <span className="muted"> ({existing} already in Keylo)</span>}
            {plan.skipped.length > 0 && <span className="muted"> · {plan.skipped.length} rows can't be imported</span>}.</p>

          <div className="form-grid">
            <div className="form-row">
              <span>Category for logins without a folder</span>
              <CategoryDropdown value={category} onChange={setCategory} categories={categories} noneLabel="None" />
            </div>
          </div>

          <div className="table-card pm-preview">
            <table className="table">
              <thead><tr><th>Name</th><th>Username</th><th>Website</th><th>Category</th></tr></thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.name} className={i.exists && !overwrite ? "muted" : undefined}>
                    <td>
                      <strong>{i.name}</strong>
                      {i.type !== "login" && <span className="chip chip-soft"> {i.type}</span>}
                      {i.hasOneTimeCode && <span className="chip chip-soft" title="Has a one-time code"> <KeyRound size={11} /> code</span>}
                      {i.exists && <span className="chip chip-soft">{overwrite ? "replaces existing" : "exists, skipped"}</span>}
                      {i.warnings.map((w) => <div key={w} className="warning small-text"><AlertTriangle size={12} /> {w}</div>)}
                    </td>
                    <td>{i.username ?? ""}</td>
                    <td className="mono small-text">{i.url ?? ""}</td>
                    <td>{i.category ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {plan.skipped.length > 0 && (
            <details className="small-text">
              <summary>{plan.skipped.length} rows won't be imported</summary>
              <ul>{plan.skipped.map((s) => <li key={s.row}>Row {s.row}{s.title ? ` (${s.title})` : ""}: {s.reason}</li>)}</ul>
            </details>
          )}

          {existing > 0 && (
            <label className="check">
              <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
              <span>Replace the {existing === 1 ? "login" : `${existing} logins`} Keylo already has with the same name</span>
            </label>
          )}
          <label className="check">
            <input type="checkbox" checked={deleteFile} onChange={(e) => setDeleteFile(e.target.checked)} />
            <span>Delete the export file afterwards: it holds every password in plain text</span>
          </label>
        </>
      )}
    </Modal>
  );
}
