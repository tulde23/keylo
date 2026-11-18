/// <reference types="vite/client" />
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { api, message, type UpdateInfo } from "../api";

const AUTO_KEY = "keylo.updates.auto";
const DISMISSED_KEY = "keylo.updates.dismissed";
const EVERY = 6 * 60 * 60 * 1000;
/** Settings → About sends this to show the notice after a manual check. */
export const SHOW_UPDATE = "keylo:show-update";

export function autoCheck(): boolean {
  try { return localStorage.getItem(AUTO_KEY) !== "off"; } catch { return true; }
}
export function setAutoCheck(on: boolean) {
  try { localStorage.setItem(AUTO_KEY, on ? "on" : "off"); } catch { /* not kept; checks stay on */ }
}
function dismissed(): string | null {
  try { return localStorage.getItem(DISMISSED_KEY); } catch { return null; }
}

/**
 * "Keylo X is available": checks a few seconds after start and every 6 hours (unless turned off in
 * Settings → About; never in a development build). Later hides it until a newer version appears.
 */
export default function UpdateNotice() {
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const check = () => {
      if (import.meta.env.DEV || !autoCheck()) return;
      api.checkUpdate()
        .then((u) => { if (u.available && dismissed() !== u.latest) setUpdate(u); })
        .catch(() => { /* offline or GitHub unreachable: try again later */ });
    };
    const first = window.setTimeout(check, 5000);
    const every = window.setInterval(check, EVERY);
    const show = (e: Event) => { setError(null); setUpdate((e as CustomEvent<UpdateInfo>).detail); };
    window.addEventListener(SHOW_UPDATE, show);
    return () => { window.clearTimeout(first); window.clearInterval(every); window.removeEventListener(SHOW_UPDATE, show); };
  }, []);

  if (!update) return null;

  const later = () => {
    try { localStorage.setItem(DISMISSED_KEY, update.latest); } catch { /* shows again next start */ }
    setUpdate(null);
  };
  const install = async () => {
    setInstalling(true);
    setError(null);
    try {
      await api.installUpdate(); // Keylo restarts when it's done.
    } catch (e) {
      setError(message(e));
      setInstalling(false);
    }
  };

  return (
    <div className="update-notice" role="status">
      <div className="update-notice-head">
        <strong>Keylo {update.latest} is available</strong>
        <button className="icon-button" aria-label="Later" title="Later" onClick={later} disabled={installing}><X size={16} /></button>
      </div>
      <p className="muted">
        You have {update.current}.{" "}
        {update.canInstall ? "Installing restarts Keylo." : update.reason}
      </p>
      {error && <p className="update-notice-error">{error}</p>}
      <div className="form-actions start">
        {update.canInstall ? (
          <button className="button primary" onClick={install} disabled={installing}>
            {installing ? "Installing…" : "Install and restart"}
          </button>
        ) : (
          <button className="button primary" onClick={() => api.openReleases().catch(() => {})}>Download</button>
        )}
        <button className="button" onClick={() => api.openReleases().catch(() => {})} disabled={installing}>What's new</button>
      </div>
    </div>
  );
}
