import { Bot, KeyRound, Lock, LifeBuoy, ScanFace, ShieldCheck } from "lucide-react";
import type { AppInfo } from "../api";

/** Settings → Help: how Keylo works, in plain terms — especially how agents reach secrets. */
export default function HelpSection({ info }: { info: AppInfo }) {
  const v = info.verifierName; // "Windows Hello" / "Touch ID" / "polkit"
  const account = `${info.platform} account`;
  return (
    <section className="card help">
      <h2>How Keylo works</h2>

      <div className="help-block">
        <h3><ShieldCheck size={16} /> Agents use secrets, they never read them</h3>
        <p className="muted">
          Keylo keeps API keys, passwords and tokens out of an AI agent's context. An agent asks Keylo to <em>run a command</em>
          with a secret (through <code>keylo run</code> or the MCP server, <code>keylo mcp</code>); the value is injected into that
          command and never returned to the agent. Values that show up in a command's output are replaced with <code>[keylo:name]</code>
          before the agent sees them.
        </p>
      </div>

      <div className="help-block">
        <h3><KeyRound size={16} /> Access keys scope what an agent can touch</h3>
        <p className="muted">
          You give each agent an <strong>access key</strong> (Settings → Agents) that covers chosen categories or secrets, or
          everything. Within that scope the agent runs commands with secrets without asking. Anything outside it needs your
          approval — a prompt that shows the exact command and reason, confirmed with {v}. Every use is written to the audit log.
        </p>
      </div>

      <div className="help-block">
        <h3><Bot size={16} /> When can an agent actually get a secret?</h3>
        <p className="muted">
          This depends on whether you've set a <strong>master passphrase</strong> (Settings → General):
        </p>
        <ul className="help-list muted">
          <li><strong>No master passphrase (default):</strong> the vault opens with your {account}, so an agent's keys always
            work — nothing for you to do.</li>
          <li><strong>Master passphrase set:</strong> the vault is locked until you unlock it. An agent can use secrets only
            while there's an unlocked session — after you unlock once it stays open about 15 minutes (shared with <code>keylo</code>
            and <code>keylo mcp</code>), and <code>keylo lock</code> ends it. For a headless machine, set <code>KEYLO_PASSPHRASE</code>.</li>
        </ul>
        <p className="muted">
          {v} unlock is only a convenience for <em>you</em> to open the vault; it doesn't change what an agent can reach, and an
          access key never needs {v}.
        </p>
      </div>

      <div className="help-block">
        <h3><Lock size={16} /> The master passphrase &amp; {v}</h3>
        <p className="muted">
          By default the vault is protected by your {account} alone. A <strong>master passphrase</strong> adds a second lock, so
          the vault can't be opened on a copied disk — or by other code running as you — without it. On {info.platform}, you can
          then unlock with <strong>{v}</strong> instead of typing the passphrase; the passphrase stays your recovery key.
        </p>
      </div>

      <div className="help-block">
        <h3><LifeBuoy size={16} /> Recovery — keep a backup</h3>
        <p className="muted">
          Your vault is tied to this {account}, so the file itself won't open on another computer. The way back in — if you forget
          the passphrase or lose this machine — is an <strong>encrypted backup</strong> (Settings → Backup), a password-protected
          file you keep somewhere other than Keylo. With sync on, another device can also recover from the join code.
        </p>
      </div>

      <div className="help-block">
        <h3><ScanFace size={16} /> The identity check</h3>
        <p className="muted">
          Reading a value yourself (<code>keylo get</code>, or revealing one in the app), and approving an agent's out-of-scope
          request, ask for {v}. You choose how often in Settings → General: once per session, every time, or never.
        </p>
      </div>

      <p className="muted small-text" style={{ marginTop: 18 }}>
        More detail is in the project README and <code>SECURITY.md</code>.
      </p>
    </section>
  );
}
