import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { FolderSync, Laptop, LogOut, QrCode, RefreshCw, Trash2 } from "lucide-react";
import { api, message, timeAgo, type SyncReport, type SyncStatus } from "../api";
import type { Run } from "../App";
import { Modal, useToast } from "./ui";

export function reportText(r: SyncReport): string {
  const parts = [r.received === 0 ? "nothing new from other devices" : `${r.received} change${r.received === 1 ? "" : "s"} received`];
  if (r.sent) parts.push(`${r.sent} change${r.sent === 1 ? "" : "s"} sent`);
  if (r.conflicts.length) parts.push(`${r.conflicts.length} conflict cop${r.conflicts.length === 1 ? "y" : "ies"} kept`);
  if (r.errors.length) parts.push(`${r.errors.length} couldn't be applied`);
  const s = parts.join(", ");
  return s[0].toUpperCase() + s.slice(1) + ".";
}

/**
 * Settings → Sync: keep secrets in step across your own devices through a folder they share
 * (OneDrive, iCloud Drive, Dropbox, Syncthing…). Keylo writes only encrypted files there.
 */
export default function SyncSection({ run, verifierName }: { run: Run; verifierName: string }) {
  const toast = useToast();
  const [status, setStatus] = useState<SyncStatus | null | undefined>(undefined);
  const [dialog, setDialog] = useState<"create" | "join" | "code" | "leave" | null>(null);
  const [syncing, setSyncing] = useState(false);

  const load = useCallback(() => {
    api.syncStatus().then(setStatus).catch(() => setStatus(null));
  }, []);
  useEffect(() => {
    load();
    const stop = listen("keylo://synced", load);
    return () => { stop.then((f) => f()); };
  }, [load]);

  const syncNow = async () => {
    setSyncing(true);
    const r = await run(() => api.syncNow());
    setSyncing(false);
    if (r) toast(reportText(r));
    load();
  };

  const forget = async (id: string, name: string) => {
    if (await run(() => api.syncForget(id)) !== undefined) {
      toast(`Removed '${name}' from the sync folder.`);
      load();
    }
  };

  if (status === undefined) return null;

  if (status === null) {
    return (
      <section className="card">
        <div className="card-header">
          <div>
            <h2>Sync</h2>
            <p className="muted">
              Keep your secrets the same on all your computers. Keylo syncs through a folder they already share (OneDrive,
              iCloud Drive, Dropbox or Syncthing) and writes only encrypted files there, readable only by devices you add
              with a code. Access keys, the activity log and settings stay on each device.
            </p>
          </div>
        </div>
        <div className="form-actions start">
          <button className="button primary" onClick={() => setDialog("create")}><FolderSync size={16} /> Start syncing…</button>
          <button className="button" onClick={() => setDialog("join")}><Laptop size={16} /> Join another device…</button>
        </div>
        {(dialog === "create" || dialog === "join") && (
          <SetUpDialog mode={dialog} run={run} onClose={() => setDialog(null)} onDone={(r) => {
            setDialog(null);
            toast(reportText(r));
            load();
          }} />
        )}
      </section>
    );
  }

  const others = status.devices.filter((d) => !d.thisDevice);
  return (
    <section className="card">
      <div className="card-header">
        <div>
          <h2>Sync</h2>
          <p className="muted">
            While Keylo is unlocked it syncs every 30 seconds, and as soon as another device's changes arrive in the folder.
            When two devices change the same secret, the newest change wins and the other is kept as "… (conflict …)".
          </p>
        </div>
      </div>
      <dl className="about">
        <dt>Folder</dt><dd className="mono">{status.folder}</dd>
        <dt>This device</dt><dd>{status.deviceName}</dd>
        <dt>Last sync</dt>
        <dd className={status.last && !status.last.ok ? "update-notice-error" : undefined}>
          {status.last ? `${timeAgo(status.last.at)} · ${status.last.summary}` : "Not yet"}
        </dd>
        {status.problem && <><dt>Problem</dt><dd className="update-notice-error">{status.problem}</dd></>}
      </dl>
      <div className="form-actions start" style={{ marginTop: 14 }}>
        <button className="button primary" onClick={syncNow} disabled={syncing}><RefreshCw size={16} /> {syncing ? "Syncing…" : "Sync now"}</button>
        <button className="button" onClick={() => setDialog("code")}><QrCode size={16} /> Add a device…</button>
        <button className="button" onClick={() => setDialog("leave")}><LogOut size={16} /> Stop syncing here…</button>
      </div>

      <h3 style={{ marginTop: 20 }}>Other devices</h3>
      {others.length === 0 ? (
        <p className="muted empty-inline">None yet. Choose Add a device to get a code, then Join on the other computer.</p>
      ) : (
        <ul className="key-list">
          {others.map((d) => (
            <li key={d.id} className="key-row">
              <Laptop size={18} />
              <div className="key-text">
                <strong>{d.name}</strong>
                <span className="muted">{d.platform} · last synced {timeAgo(d.syncedAt)}</span>
              </div>
              <button className="icon-button danger" onClick={() => forget(d.id, d.name)} aria-label={`Remove ${d.name}`}
                title="Remove its file from the folder (it still knows the code; if it syncs again, it comes back)">
                <Trash2 size={16} />
              </button>
            </li>
          ))}
        </ul>
      )}

      {dialog === "code" && <CodeDialog run={run} verifierName={verifierName} onClose={() => setDialog(null)} />}
      {dialog === "leave" && (
        <Modal title="Stop syncing on this device?" onClose={() => setDialog(null)}
          footer={<>
            <button className="button" onClick={() => setDialog(null)}>Cancel</button>
            <button className="button danger-fill" onClick={async () => {
              if (await run(() => api.syncLeave()) !== undefined) {
                setDialog(null);
                toast("Stopped syncing on this device.");
                load();
              }
            }}>Stop syncing</button>
          </>}>
          <p>This device's secrets stay here, and the other devices keep theirs. Changes stop flowing to and from this device.</p>
          <p className="muted">The other devices still have the join code. To lock out a device you no longer trust, stop syncing on
            every device and start a new sync folder.</p>
        </Modal>
      )}
    </section>
  );
}

function SetUpDialog({ mode, run, onClose, onDone }: {
  mode: "create" | "join";
  run: Run;
  onClose: () => void;
  onDone: (r: SyncReport) => void;
}) {
  const [folder, setFolder] = useState("");
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { api.syncDeviceName().then(setName).catch(() => {}); }, []);

  const pick = async () => {
    const f = await run(() => api.pickSyncFolder());
    if (f) setFolder(f);
  };
  const ready = folder && name.trim() && (mode === "create" || code.replace(/[\s-]/g, "").length === 52);
  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(mode === "create" ? await api.syncCreate(folder, name.trim()) : await api.syncJoin(folder, name.trim(), code));
    } catch (e) {
      setError(message(e));
    }
    setBusy(false);
  };

  return (
    <Modal title={mode === "create" ? "Start syncing" : "Join another device"} onClose={onClose}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={!ready || busy} onClick={go}>
          {busy ? "Syncing…" : mode === "create" ? "Start syncing" : "Join"}
        </button>
      </>}>
      <form className="form" onSubmit={(e) => { e.preventDefault(); if (ready && !busy) go(); }}>
        <p className="muted">
          {mode === "create"
            ? "Choose a folder that OneDrive, iCloud Drive, Dropbox or Syncthing keeps in sync on all your computers, such as a new \"Keylo\" folder inside it. Keylo puts an encrypted file per device there."
            : "Choose the same shared folder the other device syncs through, as it appears on this computer, and enter the code from Settings → Sync → Add a device on that device."}
        </p>
        <div className="form-row">
          <span>Folder</span>
          <div className="form-actions start">
            <button type="button" className="button" onClick={pick}>Choose folder…</button>
            {folder && <span className="mono small-text">{folder}</span>}
          </div>
        </div>
        <label className="form-row">
          <span>This device's name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={40} aria-label="Device name" />
        </label>
        {mode === "join" && (
          <label className="form-row">
            <span>Join code</span>
            <input className="mono" value={code} onChange={(e) => setCode(e.target.value)} placeholder="ABCD-EFGH-…"
              autoComplete="off" spellCheck={false} aria-label="Join code" />
          </label>
        )}
        {mode === "join" && (
          <p className="muted small-text">
            Secrets on this computer are kept. If another device has a different secret with the same name, theirs is used
            and this computer's is kept as "… (conflict …)".
          </p>
        )}
        {error && <p className="update-notice-error">{error}</p>}
      </form>
    </Modal>
  );
}

function CodeDialog({ run, verifierName, onClose }: { run: Run; verifierName: string; onClose: () => void }) {
  const [code, setCode] = useState<string | null>(null);
  return (
    <Modal title="Add a device" onClose={onClose}
      footer={<button className="button primary" onClick={onClose}>Done</button>}>
      <p>
        On the other computer, open Keylo, go to Settings → Sync → Join another device, choose the shared folder and enter this
        code (or run <span className="mono">keylo sync join FOLDER</span>).
      </p>
      {code ? (
        <p className="mono sync-code" aria-label="Join code">{code}</p>
      ) : (
        <div className="form-actions start">
          <button className="button primary" onClick={async () => { const c = await run(() => api.syncCode()); if (c) setCode(c); }}>
            Show the code ({verifierName})
          </button>
        </div>
      )}
      <p className="muted small-text">
        The code unlocks everything in the sync folder: don't send it by email or chat, and don't store it in the shared folder.
      </p>
    </Modal>
  );
}
