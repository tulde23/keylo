import { useEffect, useState } from "react";
import { AlertTriangle, Check, FilePlus, FolderPlus, X } from "lucide-react";
import { api, type CategorySummary, type ImportResult, type SecretType } from "../api";
import CategoryDropdown from "./CategoryDropdown";
import PasswordImportDialog from "./PasswordImportDialog";
import type { Run } from "../App";
import { Drawer } from "./ui";

/**
 * Import files as secrets, one per file: pick files or folders (or drop them on the window), check
 * each one's name and guessed type, then import. A folder's subfolders become categories.
 */
export default function ImportPanel({ initialPaths, types, categories, run, onClose, onImported }: {
  initialPaths: string[];
  types: SecretType[];
  categories: CategorySummary[];
  run: Run;
  onClose: () => void;
  onImported: () => void;
}) {
  const [paths, setPaths] = useState<string[]>(initialPaths);
  const [category, setCategory] = useState("");
  const [subfolders, setSubfolders] = useState(true);
  const [overwrite, setOverwrite] = useState(false);
  const [deleteOriginals, setDeleteOriginals] = useState(false);
  const [plan, setPlan] = useState<ImportResult | null>(null);
  const [names, setNames] = useState<Record<string, string>>({});
  const [chosenTypes, setChosenTypes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<(ImportResult & { deleted: number }) | null>(null);
  // One CSV exported from another password manager: offer to import its logins instead.
  const [exportFormat, setExportFormat] = useState<string | null>(null);
  const [passwordImport, setPasswordImport] = useState(false);
  useEffect(() => {
    setExportFormat(null);
    if (paths.length !== 1 || !paths[0].toLowerCase().endsWith(".csv")) return;
    let current = true;
    api.passwordExportFormat(paths[0]).then((f) => current && setExportFormat(f)).catch(() => {});
    return () => { current = false; };
  }, [paths]);

  // Files dropped on the window while this is open join the list.
  useEffect(() => {
    setPaths((p) => [...p, ...initialPaths.filter((x) => !p.includes(x))]);
  }, [initialPaths]);

  useEffect(() => {
    if (paths.length === 0) return setPlan(null);
    let current = true;
    run(() => api.importPlan(paths, category.trim() || null, subfolders)).then((p) => current && p && setPlan(p));
    return () => { current = false; };
  }, [paths, category, subfolders, run]);

  const add = async (folder: boolean) => {
    const picked = await run(() => api.pickImport(folder));
    if (picked?.length) setPaths((p) => [...p, ...picked.filter((x) => !p.includes(x))]);
  };

  const items = plan?.imported ?? [];
  const nameOf = (path: string, fallback: string) => names[path] ?? fallback;
  const typeOf = (path: string, guessed: string | null) => chosenTypes[path] ?? guessed ?? "";
  const existing = items.filter((i) => i.exists).length;
  const count = overwrite ? items.length : items.length - existing;

  const start = async () => {
    setBusy(true);
    const result = await run(() => api.importFiles({
      paths,
      category: category.trim() || null,
      subfolderCategories: subfolders,
      overwrite,
      names,
      // Every row's type as shown, so what you see is what's imported.
      types: Object.fromEntries(items.map((i) => [i.sourcePath, typeOf(i.sourcePath, i.type)])),
      deleteOriginals,
    }));
    setBusy(false);
    if (result) {
      setDone(result);
      onImported();
    }
  };

  const typeName = (id: string | null) => (id ? types.find((t) => t.id === id)?.name ?? id : "Plain");

  if (done) {
    return (
      <Drawer title="Import" onClose={onClose} footer={<button className="button primary" onClick={onClose}>Done</button>}>
        <p>
          Imported {done.imported.length === 1 ? "1 secret" : `${done.imported.length} secrets`}
          {done.skipped.length > 0 && `, skipped ${done.skipped.length}`}.
        </p>
        <ul className="import-results">
          {done.imported.map((i) => (
            <li key={i.sourcePath}><Check size={14} className="ok" /> <strong>{i.name}</strong>
              <span className="muted"> · {typeName(i.type)}{i.category ? ` · ${i.category}` : ""}</span></li>
          ))}
          {done.skipped.map((s) => (
            <li key={s.sourcePath}><X size={14} className="bad" /> <span className="mono">{fileName(s.sourcePath)}</span>
              <span className="muted"> · {s.reason}</span></li>
          ))}
        </ul>
        {done.deleted > 0 ? (
          <p className="muted">Deleted {done.deleted === 1 ? "the original file" : `${done.deleted} original files`}.</p>
        ) : done.imported.length > 0 && (
          <p className="muted">The original files are untouched. Delete them once you've checked the import.</p>
        )}
      </Drawer>
    );
  }

  return (
    <Drawer
      title="Import"
      onClose={onClose}
      dirty={paths.length > 0}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={busy || count === 0} onClick={start}>
          {busy ? "Importing…" : count === 1 ? "Import 1 secret" : `Import ${count} secrets`}
        </button>
      </>}
    >
      <p className="muted">Each file becomes a secret named after it. Keylo guesses types from names and contents (keys, tokens, database URLs).</p>
      <div className="import-pick">
        <button className="button" onClick={() => add(false)}><FilePlus size={15} /> Add files</button>
        <button className="button" onClick={() => add(true)}><FolderPlus size={15} /> Add a folder</button>
        <span className="muted small-text">or drop them on the window</span>
      </div>

      {paths.length > 0 && (
        <>
          <ul className="import-sources">
            {paths.map((p) => (
              <li key={p}>
                <span className="mono" title={p}>{p}</span>
                <button className="icon-button small" aria-label={`Remove ${p}`} onClick={() => setPaths(paths.filter((x) => x !== p))}><X size={14} /></button>
              </li>
            ))}
          </ul>

          {exportFormat && (
            <div className="pm-hint">
              <AlertTriangle size={16} />
              <div>
                <strong>This looks like a {exportFormat} export.</strong> Importing it here would store the whole file as one
                secret. Import its logins one by one instead?
                <div className="form-actions start">
                  <button className="button primary small" onClick={() => setPasswordImport(true)}>Import its logins…</button>
                </div>
              </div>
            </div>
          )}
          {passwordImport && (
            <PasswordImportDialog initialPath={paths[0]} categories={categories} run={run}
              onClose={() => setPasswordImport(false)} onImported={() => { onImported(); onClose(); }} />
          )}

          <div className="form-grid">
            <div className="form-row">
              <span>Category for everything</span>
              <CategoryDropdown value={category} onChange={setCategory} categories={categories}
                noneLabel={subfolders ? "From subfolders" : "None"} />
            </div>
          </div>
          <label className="check">
            <input type="checkbox" checked={subfolders} disabled={!!category.trim()} onChange={(e) => setSubfolders(e.target.checked)} />
            <span>A folder's subfolders become categories</span>
          </label>

          {items.length > 0 && (
            <table className="import-table">
              <thead><tr><th>Secret</th><th>Type</th><th>Category</th></tr></thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.sourcePath} className={i.exists && !overwrite ? "skipping" : undefined}>
                    <td>
                      <input value={nameOf(i.sourcePath, i.name)} aria-label={`Name for ${fileName(i.sourcePath)}`} maxLength={128}
                        onChange={(e) => setNames({ ...names, [i.sourcePath]: e.target.value })} />
                      <small className="muted" title={i.sourcePath}>
                        {fileName(i.sourcePath)}
                        {i.exists && (overwrite ? " · replaces the existing one" : " · exists, skipped")}
                      </small>
                    </td>
                    <td>
                      <select value={typeOf(i.sourcePath, i.type)} aria-label={`Type for ${fileName(i.sourcePath)}`}
                        onChange={(e) => setChosenTypes({ ...chosenTypes, [i.sourcePath]: e.target.value })}>
                        <option value="">Plain</option>
                        {types.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
                      </select>
                    </td>
                    <td className="muted">{i.category ?? "None"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {plan && plan.skipped.length > 0 && (
            <ul className="import-results">
              {plan.skipped.map((s) => (
                <li key={s.sourcePath}><X size={14} className="bad" /> <span className="mono">{fileName(s.sourcePath)}</span>
                  <span className="muted"> · {s.reason}</span></li>
              ))}
            </ul>
          )}
          {plan && items.length === 0 && plan.skipped.length === 0 && <p className="muted">No files there.</p>}

          {existing > 0 && (
            <label className="check">
              <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
              <span>Replace the {existing === 1 ? "secret that already exists" : `${existing} secrets that already exist`}</span>
            </label>
          )}
          <label className="check">
            <input type="checkbox" checked={deleteOriginals} onChange={(e) => setDeleteOriginals(e.target.checked)} />
            <span>Delete the original files afterwards</span>
          </label>
          {deleteOriginals && (
            <p className="warning small-text"><AlertTriangle size={14} /> They're overwritten with zeros, then deleted. Files that fail to import are kept.</p>
          )}
        </>
      )}
    </Drawer>
  );
}

function fileName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}
