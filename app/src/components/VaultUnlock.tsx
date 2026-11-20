import { useEffect, useState } from "react";
import { KeyRound, ScanFace } from "lucide-react";
import { api, message, type AppInfo } from "../api";

/** Shown when the vault has a master passphrase and isn't open yet: nothing can be read until it is. */
export default function VaultUnlock({ info, onUnlocked }: { info: AppInfo; onUnlocked: () => Promise<void> }) {
  const [passphrase, setPassphrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hello, setHello] = useState(false);

  // Offer "Unlock with Windows Hello" only when it's set up for this vault.
  useEffect(() => {
    if (info.platform !== "Windows") return;
    api.vaultHasHello().then(setHello).catch(() => setHello(false));
  }, [info.platform]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.vaultUnlock(passphrase);
      setPassphrase("");
      await onUnlocked();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  const unlockHello = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.vaultUnlockHello();
      await onUnlocked();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="lock-screen">
      <div className="lock-card">
        <img src="/keylo.svg" alt="" className="lock-logo" />
        <h1>Keylo is locked</h1>
        <p className="muted">Enter your master passphrase to open the vault.</p>
        <form className="form" onSubmit={submit}>
          <input type="password" autoFocus value={passphrase} onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Master passphrase" aria-label="Master passphrase" autoComplete="current-password" />
          <button className="button primary large" type="submit" disabled={busy || !passphrase}>
            <KeyRound size={18} /> {busy ? "Unlocking…" : "Unlock"}
          </button>
        </form>
        {hello && (
          <button className="button large" type="button" onClick={unlockHello} disabled={busy} style={{ marginTop: 10 }}>
            <ScanFace size={18} /> Unlock with Windows Hello
          </button>
        )}
        {error && <p className="error-text">{error}</p>}
        <p className="lock-footer">Agents never see your secrets' values.<br />Keylo {info.version}</p>
      </div>
    </main>
  );
}
