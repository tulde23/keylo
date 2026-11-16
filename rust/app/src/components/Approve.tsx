import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { api, message, type Approval } from "../api";

/** keylow --approve: an agent asks to use secrets its key doesn't cover. Exits with the answer. */
export default function Approve() {
  const [request, setRequest] = useState<Approval | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.approval().then(setRequest);
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
        <button className="button" onClick={() => answer("deny")} disabled={busy} autoFocus>Deny</button>
        <span className="toolbar-gap" />
        {request.grantOnly ? (
          <button className="button primary" onClick={() => answer("always")} disabled={busy}>Add to its key</button>
        ) : (
          <>
            {request.canAlwaysAllow && (
              <button className="button" onClick={() => answer("always")} disabled={busy} title="Adds these secrets to the agent's access key">
                Always allow
              </button>
            )}
            <button className="button primary" onClick={() => answer("once")} disabled={busy}>Allow once</button>
          </>
        )}
      </footer>
    </main>
  );
}
