import { useState } from "react";
import { ArchiveRestore, HardDriveDownload } from "lucide-react";
import { api, type BackupPreview } from "../api";
import type { Run } from "../App";
import { Modal, useToast } from "./ui";

/**
 * Password-protected backups of every secret, category, custom type and icon, portable to another
 * PC or Mac (and to the C# Keylo). Restoring skips secrets that exist unless you choose to replace them.
 */
export default function BackupSection({ run, verifierName, onRestored }: {
  run: Run;
  verifierName: string;
  onRestored: () => void;
}) {
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
