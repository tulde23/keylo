import type { AppInfo } from "../api";

/**
 * Shown between unlocking and the first load finishing — so a slow vault (large store, or just after a
 * reinstall when it's migrating) never flashes an empty "no secrets" screen. Branded, calm, themed.
 */
export default function VaultLoading({ info }: { info: AppInfo | null }) {
  return (
    <main className="lock-screen">
      <div className="lock-card vault-loading">
        <div className="vault-loading-logo">
          <span className="vault-loading-ring" />
          <span className="vault-loading-ring" />
          <img src="/keylo.svg" alt="" />
        </div>
        <h1>Opening your vault</h1>
        <p className="muted">Decrypting and loading your secrets…</p>
        <div className="vault-loading-bar">
          <span />
        </div>
        {info && <p className="lock-footer">Keylo {info.version}</p>}
      </div>
    </main>
  );
}
