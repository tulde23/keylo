import { useState } from "react";
import { ArchiveRestore, FileDown, FileUp, HardDriveDownload } from "lucide-react";
import { api, type BackupPreview, type CategorySummary, type ExportFormat, type PasswordExport } from "../api";
import PasswordImportDialog from "./PasswordImportDialog";
import type { Run } from "../App";
import { Modal, useToast } from "./ui";

/**
 * Password-protected backups of every secret, category, custom type and icon, portable to another
 * PC or Mac. Restoring skips secrets that exist unless you choose to replace them.
 */
export default function BackupSection({ run, verifierName, categories, onRestored }: {
  run: Run;
  verifierName: string;
  categories: CategorySummary[];
  onRestored: () => void;
}) {
  const [importing, setImporting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [backingUp, setBackingUp] = useState<string | null>(null);
  const [restoring, setRestoring] = useState<string | null>(null);

  const backUp = async () => {
    const path = await run(() => api.pickBackup(true));
    if (path) setBackingUp(path);
  };
  const restore = async () => {
    const path = await run(() => api.pickBackup(false));
    if (path) setRestoring(path);
  };

  return (
    <>
    <section className="card">
      <div className="card-header">
        <div>
          <h2>Other password managers</h2>
          <p className="muted">
            Bring your logins over from Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass, KeePassXC or Apple Passwords: export
            them as CSV there, then choose the file. You'll see every login before anything is imported. Or export your secrets as
            a CSV that another password manager can import.
          </p>
        </div>
      </div>
      <div className="form-actions start">
        <button className="button primary" onClick={() => setImporting(true)}><FileUp size={16} /> Import passwords…</button>
        <button className="button" onClick={() => setExporting(true)}><FileDown size={16} /> Export passwords…</button>
      </div>
      {importing && <PasswordImportDialog initialPath={null} categories={categories} run={run} onClose={() => setImporting(false)} onImported={onRestored} />}
      {exporting && <PasswordExportDialog categories={categories} run={run} onClose={() => setExporting(false)} />}
    </section>
    <section className="card">
      <div className="card-header">
        <div>
          <h2>Backup</h2>
          <p className="muted">
            One file with every secret, category, custom type and icon, encrypted with a password you choose. It opens on any
            PC or Mac with Keylo, which your {verifierName}-protected store can't. Keep the password somewhere other than Keylo.
          </p>
        </div>
      </div>
      <div className="form-actions start">
        <button className="button primary" onClick={backUp}><HardDriveDownload size={16} /> Back up…</button>
        <button className="button" onClick={restore}><ArchiveRestore size={16} /> Restore…</button>
      </div>
      {backingUp && <BackupDialog path={backingUp} run={run} onClose={() => setBackingUp(null)} />}
      {restoring && <RestoreDialog path={restoring} run={run} onClose={() => setRestoring(null)} onRestored={onRestored} />}
    </section>
    </>
  );
}

function BackupDialog({ path, run, onClose }: { path: string; run: Run; onClose: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const short = password.length > 0 && password.length < 10;
  const mismatch = again.length > 0 && again !== password;

  const create = async () => {
    setBusy(true);
    const summary = await run(() => api.createBackup(path, password));
    setBusy(false);
    if (summary) {
      toast(`Backed up ${summary.secrets} secrets to ${fileName(summary.path)}.`);
      onClose();
    }
  };

  return (
    <Modal title="Back up Keylo" onClose={onClose}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={busy || password.length < 10 || again !== password} onClick={create}>
          {busy ? "Encrypting…" : "Back up"}
        </button>
      </>}>
      <form className="form" onSubmit={(e) => { e.preventDefault(); if (password.length >= 10 && again === password) create(); }}>
        <p className="mono small-text">{path}</p>
        <label className="form-row">
          <span>Backup password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus autoComplete="new-password" aria-label="Backup password" />
        </label>
        {short && <small className="muted">At least 10 characters; a passphrase of a few words is ideal.</small>}
        <label className="form-row">
          <span>Again</span>
          <input type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" aria-label="Confirm backup password" />
        </label>
        {mismatch && <small className="bad">The passwords don't match.</small>}
        <p className="muted small-text">Without this password the backup can't be opened, by you or anyone else.</p>
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

const EXPORT_FORMATS: { value: ExportFormat; label: string; description: string }[] = [
  {
    value: "bitwarden",
    label: "Bitwarden",
    description: "For Bitwarden, and other apps that can import a Bitwarden CSV. Keeps categories as folders, one-time codes and extra fields; keys and notes become secure notes.",
  },
  {
    value: "browser",
    label: "Browser and others",
    description: "The CSV Chrome exports: for Chrome, Edge, Brave, Firefox, Apple Passwords, KeePassXC and most password managers. Passwords only: keys and notes are left out, and one-time codes and extra fields go in the note.",
  },
];

function PasswordExportDialog({ categories, run, onClose }: { categories: CategorySummary[]; run: Run; onClose: () => void }) {
  const toast = useToast();
  const [format, setFormat] = useState<ExportFormat>("bitwarden");
  const [category, setCategory] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PasswordExport | null>(null);

  const save = async () => {
    const path = await run(() => api.pickPasswordExportSave(format));
    if (!path) return;
    setBusy(true);
    const r = await run(() => api.exportPasswords(path, format, category || null));
    setBusy(false);
    if (!r) return;
    if (r.skipped.length) setResult(r);
    else {
      toast(`Exported ${plural(r.exported, "secret")} to ${fileName(r.path)}. Delete it once it's imported.`);
      onClose();
    }
  };

  if (result) {
    return (
      <Modal title="Exported" onClose={onClose} footer={<button className="button primary" onClick={onClose}>Done</button>}>
        <p>Exported {plural(result.exported, "secret")} to <span className="mono small-text">{result.path}</span>.</p>
        <p>Left out:</p>
        <ul className="import-results">{result.skipped.map((s) => <li key={s.name}><strong>{s.name}</strong>: {s.reason}</li>)}</ul>
        <p className="muted small-text">The file holds every exported password in plain text. Delete it once it's imported, and empty the recycle bin.</p>
      </Modal>
    );
  }

  return (
    <Modal title="Export passwords" onClose={onClose}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={busy} onClick={save}>{busy ? "Exporting…" : "Export…"}</button>
      </>}>
      <div className="form">
        <div className="theme-grid" role="radiogroup" aria-label="Format">
          {EXPORT_FORMATS.map((f) => (
            <button key={f.value} type="button" role="radio" aria-checked={format === f.value}
              className={`theme-option${format === f.value ? " active" : ""}`} onClick={() => setFormat(f.value)}>
              <span>
                <strong>{f.label}</strong>
                <small className="muted">{f.description}</small>
              </span>
            </button>
          ))}
        </div>
        <label className="form-row">
          <span>Secrets</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Which secrets">
            <option value="">All secrets</option>
            {categories.map((c) => <option key={c.name} value={c.name}>{c.name}</option>)}
          </select>
        </label>
        <p className="notice small-text">
          The file holds the passwords in <strong>plain text</strong>, readable by anyone who gets it. Save it somewhere that
          doesn't sync, import it, then delete it. Linked secrets (1Password, AWS) are left out.
        </p>
      </div>
    </Modal>
  );
}

function RestoreDialog({ path, run, onClose, onRestored }: { path: string; run: Run; onClose: () => void; onRestored: () => void }) {
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [overwrite, setOverwrite] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<string[] | null>(null);

  const close = () => {
    if (preview) api.cancelRestore().catch(() => {});
    onClose();
  };

  const open = async () => {
    setBusy(true);
    const p = await run(() => api.openBackup(path, password));
    setBusy(false);
    setPassword("");
    if (p) setPreview(p);
  };

  const restore = async () => {
    setBusy(true);
    const r = await run(() => api.restoreBackup(overwrite));
    setBusy(false);
    if (!r) return;
    onRestored();
    const parts = [`${r.added} added`];
    if (r.replaced) parts.push(`${r.replaced} replaced`);
    if (r.skipped) parts.push(`${r.skipped} skipped`);
    toast(`Restored: ${parts.join(", ")}.`, r.errors.length > 0);
    if (r.errors.length) setErrors(r.errors);
    else onClose();
  };

  if (errors) {
    return (
      <Modal title="Restored, with problems" onClose={onClose} footer={<button className="button primary" onClick={onClose}>Done</button>}>
        <p>These secrets couldn't be restored:</p>
        <ul className="import-results">{errors.map((e) => <li key={e}>{e}</li>)}</ul>
      </Modal>
    );
  }

  if (!preview) {
    return (
      <Modal title="Restore a backup" onClose={close}
        footer={<>
          <button className="button" onClick={close}>Cancel</button>
          <button className="button primary" disabled={busy || !password} onClick={open}>{busy ? "Decrypting…" : "Open"}</button>
        </>}>
        <form className="form" onSubmit={(e) => { e.preventDefault(); if (password) open(); }}>
          <p className="mono small-text">{path}</p>
          <label className="form-row">
            <span>Backup password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoFocus aria-label="Backup password" />
          </label>
          <button type="submit" hidden />
        </form>
      </Modal>
    );
  }

  const fresh = preview.secrets - preview.existing;
  return (
    <Modal title="Restore a backup" onClose={close}
      footer={<>
        <button className="button" onClick={close}>Cancel</button>
        <button className="button primary" disabled={busy || (fresh === 0 && !overwrite)} onClick={restore}>{busy ? "Restoring…" : "Restore"}</button>
      </>}>
      <p>
        Backed up {new Date(preview.createdAt).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}:{" "}
        {[
          plural(preview.secrets, "secret"),
          preview.categories > 0 && plural(preview.categories, "category", "categories"),
          preview.types > 0 && plural(preview.types, "custom type"),
          preview.icons > 0 && plural(preview.icons, "icon"),
        ].filter(Boolean).join(", ")}.
      </p>
      {preview.existing === 0 ? (
        <p className="muted">None of them are here yet; all {preview.secrets} will be added.</p>
      ) : (
        <>
          <p className="muted">
            {preview.existing === preview.secrets ? "All of them are" : `${preview.existing} of them are`} already here.
            {fresh > 0 && ` ${fresh} will be added.`}
          </p>
          <label className="check">
            <input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} />
            <span>Replace the {preview.existing === 1 ? "one that's" : `${preview.existing} that are`} here with the backup's</span>
          </label>
        </>
      )}
    </Modal>
  );
}

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

function fileName(path: string) {
  return path.split(/[\\/]/).pop() ?? path;
}
