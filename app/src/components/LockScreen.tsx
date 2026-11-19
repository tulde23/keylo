import { useState } from "react";
import { Fingerprint } from "lucide-react";
import { message, type AppInfo } from "../api";

export default function LockScreen({ info, onUnlock }: { info: AppInfo; onUnlock: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const unlock = async () => {
    setBusy(true);
    setError(null);
    try {
      await onUnlock();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };

  // No automatic prompt: Hello asks only when Unlock is clicked (or Enter pressed — it has focus).

  return (
    <main className="lock-screen">
      <div className="lock-card">
        <img src="/keylo.svg" alt="" className="lock-logo" />
        <h1>Keylo is locked</h1>
        <p className="muted">Your secrets are in {info.storeName}. Unlock with {info.verifierName} to see them.</p>
        <button className="button primary large" onClick={unlock} disabled={busy} autoFocus>
          <Fingerprint size={18} /> {busy ? `Waiting for ${info.verifierName}…` : "Unlock"}
        </button>
        {error && <p className="error-text">{error}</p>}
        <p className="lock-footer">Agents never see your secrets' values.<br />Keylo {info.version}</p>
      </div>
    </main>
  );
}
