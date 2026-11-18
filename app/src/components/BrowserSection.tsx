import { useEffect, useState } from "react";
import { Globe, Link2, Unlink } from "lucide-react";
import { api, type BrowserStatus } from "../api";
import type { Run } from "../App";
import { useToast } from "./ui";

/**
 * Settings → Browser: lets the Keylo extension in each browser reach Keylo (native messaging), and
 * explains how to add the extension.
 */
export default function BrowserSection({ run, verifierName }: { run: Run; verifierName: string }) {
  const toast = useToast();
  const [browsers, setBrowsers] = useState<BrowserStatus[] | null>(null);

  useEffect(() => {
    run(() => api.browserStatus()).then((b) => b && setBrowsers(b));
  }, [run]);

  const toggle = async (b: BrowserStatus) => {
    const next = await run(() => (b.connected ? api.browserDisconnect(b.id) : api.browserConnect(b.id)));
    if (next) {
      setBrowsers(next);
      toast(b.connected ? `Disconnected ${b.name}.` : `Connected ${b.name}. Restart it if the extension can't reach Keylo.`);
    }
  };

  const shown = (browsers ?? []).filter((b) => b.detected || b.connected || b.elsewhere);

  return (
    <>
      <section className="card">
        <div className="card-header">
          <div>
            <h2>Browser</h2>
            <p className="muted">
              The Keylo extension fills your logins in Chrome, Edge, Brave and Firefox. It only fills a login on the site it's
              saved for, only when you click Fill (or press Ctrl+Shift+L), after {verifierName} or within your session, and never in a
              browser controlled by an agent or test tool. Each fill appears in Activity.
            </p>
          </div>
        </div>

        {browsers === null ? null : shown.length === 0 ? (
          <p className="muted">No supported browser was found.</p>
        ) : (
          <ul className="key-list">
            {shown.map((b) => (
              <li key={b.id} className="key-row">
                <Globe size={18} />
                <div className="key-text">
                  <strong>{b.name}</strong>
                  <span className="muted">
                    {b.connected ? "Connected: the extension can reach Keylo" : b.elsewhere ? `Connected to another keylo (${b.elsewhere})` : "Not connected"}
                  </span>
                </div>
                <button className={`button small${b.connected ? "" : " primary"}`} onClick={() => toggle(b)}>
                  {b.connected ? <><Unlink size={14} /> Disconnect</> : <><Link2 size={14} /> Connect</>}
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h2>Adding the extension</h2>
        <p className="muted">It isn't in the browsers' stores yet, so add it from the release:</p>
        <ol className="steps">
          <li>Download <span className="mono">keylo-…-browser-chrome.zip</span> (or <span className="mono">-firefox.zip</span>) from the
            latest release and unzip it somewhere it can stay.</li>
          <li><strong>Chrome, Edge, Brave:</strong> open the extensions page (<span className="mono">chrome://extensions</span>,{" "}
            <span className="mono">edge://extensions</span>), turn on <em>Developer mode</em>, choose <em>Load unpacked</em> and pick the
            unzipped folder.</li>
          <li><strong>Firefox:</strong> open <span className="mono">about:debugging#/runtime/this-firefox</span> and choose{" "}
            <em>Load Temporary Add-on</em> (Firefox removes it when it restarts, until the extension is signed).</li>
          <li>Connect the browser above, then restart it.</li>
        </ol>
        <div className="form-actions start">
          <button className="button" onClick={() => api.openReleases().catch(() => {})}>Open the latest release</button>
        </div>
      </section>
    </>
  );
}
