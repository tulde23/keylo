import { useEffect, useState } from "react";
import { Eye, EyeOff, KeyRound, LifeBuoy, ScanFace, ShieldPlus, Trash2, Wand2, X } from "lucide-react";
import { api } from "../api";
import type { Run } from "../App";
import { BackupDialog } from "./BackupSection";
import { Modal, useToast } from "./ui";

/**
 * Settings → General: an optional master passphrase on top of the OS protection, and a biometric
 * unlock (Windows Hello / Touch ID) on top of that. Without the passphrase the vault opens with your
 * OS account alone; with it, the vault can't be opened on a copied disk, or by other code running as
 * you, without the passphrase. Windows and macOS.
 */
export default function VaultSecuritySection({ run, platform, verifierName }: { run: Run; platform: string; verifierName: string }) {
  const [has, setHas] = useState<boolean | null>(null);
  const [dialog, setDialog] = useState<"set" | "change" | "remove" | null>(null);
  const [helloOk, setHelloOk] = useState(false);
  const [helloOn, setHelloOn] = useState(false);
  const [helloBusy, setHelloBusy] = useState(false);
  const [nudge, setNudge] = useState(false);
  const [backupPath, setBackupPath] = useState<string | null>(null);
  const toast = useToast();

  const refresh = () => {
    run(() => api.vaultHasPassphrase()).then((h) => h !== undefined && setHas(h));
    api.helloAvailable().then(setHelloOk).catch(() => setHelloOk(false));
    api.vaultHasHello().then(setHelloOn).catch(() => setHelloOn(false));
  };
  useEffect(() => { refresh(); }, []);

  const toggleHello = async () => {
    setHelloBusy(true);
    const turningOn = !helloOn;
    const ok = await run(() => api.setVaultHello(turningOn, null));
    setHelloBusy(false);
    if (ok !== undefined) {
      toast(turningOn ? `${verifierName} unlock turned on.` : `${verifierName} unlock turned off.`);
      setHelloOn(turningOn);
      if (turningOn) setNudge(true);
    }
  };

  // Offer a recovery backup after a strong factor is set up: it's the only portable way back in if the
  // passphrase is forgotten or this PC is lost (the vault file itself is tied to this account).
  const startBackup = async () => {
    const path = await run(() => api.pickBackup(true));
    if (path) setBackupPath(path);
  };

  if ((platform !== "Windows" && platform !== "macOS") || has === null) return null;
  // Where the biometric unlock key is bound, for the explanatory copy.
  const boundTo = platform === "macOS" ? "this Mac's Secure Enclave" : "this PC's TPM";

  return (
    <section className="card">
      <div className="card-header">
        <div>
          <h2>Master passphrase</h2>
          <p className="muted">
            An extra passphrase on top of your {platform} account. With one set, the vault can't be opened on a copied
            disk, or by other programs running as you, without it. You'll enter it when Keylo starts.
            {has ? " A master passphrase is set." : " None is set; the vault opens with your account alone."}
          </p>
        </div>
      </div>
      <div className="form-actions start">
        {has ? (
          <>
            <button className="button" onClick={() => setDialog("change")}><KeyRound size={16} /> Change…</button>
            <button className="button danger-fill" onClick={() => setDialog("remove")}><Trash2 size={16} /> Remove…</button>
          </>
        ) : (
          <button className="button primary" onClick={() => setDialog("set")}><ShieldPlus size={16} /> Set a master passphrase…</button>
        )}
      </div>
      {has && helloOk && (
        <div style={{ marginTop: 18, paddingTop: 18, borderTop: "1px solid var(--border, rgba(128,128,128,0.25))" }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 6, margin: "0 0 4px" }}>
            <ScanFace size={16} /> Unlock with {verifierName}
          </h3>
          <p className="muted">
            {helloOn
              ? `Open the vault with ${verifierName} instead of typing the passphrase. Your passphrase still works and stays your recovery key.`
              : `Skip typing the passphrase: unlock with ${verifierName}. The key is bound to ${boundTo}; your passphrase remains the way to recover if the ${verifierName} key is ever lost.`}
          </p>
          <div className="form-actions start">
            <button className={`button ${helloOn ? "" : "primary"}`} disabled={helloBusy} onClick={toggleHello}>
              {helloBusy ? "Working…" : helloOn ? `Turn off ${verifierName} unlock` : "Turn on…"}
            </button>
          </div>
        </div>
      )}
      {nudge && (
        <div className="notice" style={{ marginTop: 16, display: "flex", gap: 10, alignItems: "flex-start" }}>
          <LifeBuoy size={18} style={{ flexShrink: 0, marginTop: 2 }} />
          <div style={{ flex: 1 }}>
            <strong>Make a recovery backup — your emergency kit.</strong>
            <p className="muted small-text" style={{ margin: "4px 0 8px" }}>
              Your vault is tied to this {platform} account, so the file can't be opened on another computer. If you forget the
              passphrase or lose this machine, a password-protected backup kept somewhere else (not Keylo) is the only way back in.
            </p>
            <button className="button primary" onClick={startBackup}><LifeBuoy size={16} /> Create recovery backup…</button>
          </div>
          <button className="icon-button" aria-label="Dismiss" onClick={() => setNudge(false)}><X size={16} /></button>
        </div>
      )}
      {dialog && <PassphraseDialog mode={dialog} run={run} onClose={() => setDialog(null)}
        onDone={(mode) => { setDialog(null); refresh(); if (mode === "set") setNudge(true); }} />}
      {backupPath && <BackupDialog path={backupPath} run={run} onClose={() => { setBackupPath(null); setNudge(false); }} />}
    </section>
  );
}

function PassphraseDialog({ mode, run, onClose, onDone }: { mode: "set" | "change" | "remove"; run: Run; onClose: () => void; onDone: (mode: "set" | "change" | "remove") => void }) {
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);

  const generate = async () => {
    const p = await run(() => api.generatePassphrase(6));
    if (p) { setNext(p); setAgain(p); setShow(true); }
  };

  const needsCurrent = mode !== "set";
  const needsNew = mode !== "remove";
  const shortNew = needsNew && next.length > 0 && next.length < 10;
  const mismatch = needsNew && again.length > 0 && again !== next;
  const ready = (!needsCurrent || current.length > 0) && (!needsNew || (next.length >= 10 && again === next));

  const apply = async () => {
    setBusy(true);
    const ok = await run(() => api.setVaultPassphrase(needsCurrent ? current : null, needsNew ? next : null));
    setBusy(false);
    if (ok !== undefined) {
      toast(mode === "set" ? "Master passphrase set." : mode === "change" ? "Master passphrase changed." : "Master passphrase removed.");
      onDone(mode);
    }
  };

  const title = mode === "set" ? "Set a master passphrase" : mode === "change" ? "Change the master passphrase" : "Remove the master passphrase";
  return (
    <Modal title={title} onClose={onClose}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className={`button ${mode === "remove" ? "danger-fill" : "primary"}`} disabled={busy || !ready} onClick={apply}>
          {busy ? "Working…" : mode === "remove" ? "Remove" : "Save"}
        </button>
      </>}>
      <form className="form" onSubmit={(e) => { e.preventDefault(); if (ready && !busy) apply(); }}>
        {needsCurrent && (
          <label className="form-row">
            <span>Current passphrase</span>
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoFocus aria-label="Current passphrase" autoComplete="current-password" />
          </label>
        )}
        {needsNew && (
          <>
            <label className="form-row">
              <span>New passphrase</span>
              <div style={{ display: "flex", gap: 6 }}>
                <input style={{ flex: 1 }} type={show ? "text" : "password"} value={next} onChange={(e) => setNext(e.target.value)} autoFocus={!needsCurrent} aria-label="New passphrase" autoComplete="new-password" />
                <button type="button" className="icon-button" onClick={() => setShow(!show)} title={show ? "Hide" : "Show"} aria-label={show ? "Hide" : "Show"}>{show ? <EyeOff size={16} /> : <Eye size={16} />}</button>
                <button type="button" className="icon-button" onClick={generate} title="Generate a memorable passphrase" aria-label="Generate a memorable passphrase"><Wand2 size={16} /></button>
              </div>
            </label>
            {shortNew && <small className="muted">At least 10 characters; a passphrase of a few words is ideal — or use the wand for a strong, memorable one.</small>}
            <label className="form-row">
              <span>Again</span>
              <input type="password" value={again} onChange={(e) => setAgain(e.target.value)} aria-label="Confirm new passphrase" autoComplete="new-password" />
            </label>
            {mismatch && <small className="bad">The passphrases don't match.</small>}
          </>
        )}
        {mode === "remove" && <p className="muted small-text">The vault will open with your {"Windows"} account alone again.</p>}
        {needsNew && <p className="muted small-text">Without this passphrase the vault can't be opened on another machine. Keep it somewhere safe.</p>}
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}
