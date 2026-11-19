import { useEffect, useState } from "react";
import { KeyRound, ShieldPlus, Trash2 } from "lucide-react";
import { api } from "../api";
import type { Run } from "../App";
import { Modal, useToast } from "./ui";

/**
 * Settings → General: an optional master passphrase on top of the OS protection. Without it the vault
 * opens with your OS account alone; with it, the vault can't be opened on a copied disk, or by other
 * code running as you, without the passphrase. Windows only for now.
 */
export default function VaultSecuritySection({ run, platform }: { run: Run; platform: string }) {
  const [has, setHas] = useState<boolean | null>(null);
  const [dialog, setDialog] = useState<"set" | "change" | "remove" | null>(null);

  const refresh = () => run(() => api.vaultHasPassphrase()).then((h) => h !== undefined && setHas(h));
  useEffect(() => { refresh(); }, []);

  if (platform !== "Windows" || has === null) return null;

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
      {dialog && <PassphraseDialog mode={dialog} run={run} onClose={() => setDialog(null)} onDone={() => { setDialog(null); refresh(); }} />}
    </section>
  );
}

function PassphraseDialog({ mode, run, onClose, onDone }: { mode: "set" | "change" | "remove"; run: Run; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);

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
      onDone();
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
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} autoFocus={!needsCurrent} aria-label="New passphrase" autoComplete="new-password" />
            </label>
            {shortNew && <small className="muted">At least 10 characters; a passphrase of a few words is ideal.</small>}
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
