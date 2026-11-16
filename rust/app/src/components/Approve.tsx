import { useEffect, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { api, message, type Approval } from "../api";

/** keylow --approve: an agent asks to use secrets its key doesn't cover. Exits with the answer. */
export default function Approve() {
  const [request, setRequest] = useState<Approval | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The window opens on top and takes focus; a click or key press meant for another window mustn't
  // answer it, so the buttons wake up a moment after it appears.
  const [ready, setReady] = useState(false);
  const deny = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (ready) deny.current?.focus(); // the safe answer has the keyboard
  }, [ready]);

  useEffect(() => {
    api.approval().then((r) => {
      setRequest(r);
      setTimeout(() => setReady(true), 800);
    });
  }, []);

  if (!request) return <div className="splash" />;

  const agent = request.keyName || "An agent";
  const count = request.secrets.length === 1 ? "a secret" : `${request.secrets.length} secrets`;
  const title = request.grantOnly ? `${agent} wants permanent access to ${count}` : `${agent} wants to use ${count}`;

  const answer = async (choice: "deny" | "once" | "always") => {
    setBusy(true);
    setError(null);
    try {
      await api.answerApproval(choice);
    } catch (e) {
      setError(message(e));
      setBusy(false);
    }
  };

  return (
    <main className="approve">
      <header className="approve-header">
        <ShieldAlert size={28} />
        <h1>{title}</h1>
      </header>
      <ul className="approve-secrets">
        {request.secrets.map((s) => <li key={s}><code>{s}</code></li>)}
      </ul>
      {request.command && (
        <section>
          <h2>Command</h2>
          <pre className="approve-text">{request.command}</pre>
        </section>
      )}
      {request.reason && (
        <section>
          <h2>Reason given by the agent</h2>
          <p className="approve-text">“{request.reason.trim()}”</p>
        </section>
      )}
      <p className="muted small-text">
        The agent won't see the values: they go to the command as environment variables. Allowing asks for {request.verifierName}.
      </p>
      {error && <p className="error-text">{error}</p>}
      <footer className="approve-actions">
        <button ref={deny} className="button" onClick={() => answer("deny")} disabled={busy || !ready}>Deny</button>
        <span className="toolbar-gap" />
        {request.grantOnly ? (
          <button className="button primary" onClick={() => answer("always")} disabled={busy || !ready}>Add to its key</button>
        ) : (
          <>
            {request.canAlwaysAllow && (
              <button className="button" onClick={() => answer("always")} disabled={busy || !ready} title="Adds these secrets to the agent's access key">
                Always allow
              </button>
            )}
            <button className="button primary" onClick={() => answer("once")} disabled={busy || !ready}>Allow once</button>
          </>
        )}
      </footer>
    </main>
  );
}
