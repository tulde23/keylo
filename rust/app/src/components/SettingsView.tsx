import { useEffect, useState } from "react";
import { Copy, KeyRound, Plus, Trash2 } from "lucide-react";
import { api, timeAgo, type AccessKey, type AppInfo, type KeyInput, type Secret, type SecretType, type Settings } from "../api";
import TypesSection from "./TypesSection";
import BackupSection from "./BackupSection";
import VaultsSection from "./VaultsSection";
import type { Run } from "../App";
import { Drawer, Modal, useToast } from "./ui";

export default function SettingsView(props: {
  info: AppInfo;
  secrets: Secret[];
  types: SecretType[];
  onTypes: (types: SecretType[]) => void;
  categories: string[];
  run: Run;
  onSettingsSaved: () => Promise<void>;
  onDataChanged: () => void;
}) {
  const { info, run } = props;
  const toast = useToast();
  const [saved, setSaved] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [keys, setKeys] = useState<AccessKey[]>([]);
  const [keyEditor, setKeyEditor] = useState<AccessKey | "new" | null>(null);
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);

  const loadKeys = () => run(api.keys).then((k) => k && setKeys(k));
  useEffect(() => {
    run(api.settings).then((s) => { if (s) { setSaved(s); setDraft(s); } });
    loadKeys();
  }, []);

  const dirty = saved && draft && JSON.stringify(saved) !== JSON.stringify(draft);
  const saveSettings = async () => {
    if (!draft) return;
    const s = await run(() => api.saveSettings(draft));
    if (s) {
      setSaved(s);
      setDraft(s);
      toast("Settings saved.");
      await props.onSettingsSaved();
    }
  };

  const revoke = async (k: AccessKey) => {
    const done = await run(async () => { await api.revokeKey(k.id); return true; });
    if (done) {
      toast(`Revoked '${k.name}'.`);
      loadKeys();
    }
  };

  const claudeCommand = (t: string) =>
    `claude mcp add keylo --scope user --env KEYLO_ACCESS_KEY=${t} -- "${info.keyloPath}" mcp`;

  return (
    <main className="page">
      <h1>Settings</h1>

      <section className="card">
        <h2>Identity check</h2>
        <p className="muted">When Keylo asks for {info.verifierName}. Changing these asks for it too.</p>
        {draft && (
          <div className="form">
            <fieldset className="radio-group">
              <legend>Ask for {info.verifierName}</legend>
              {([
                ["session", "Once per session", `Then Keylo stays unlocked while you use it (the app and the keylo command share the session).`],
                ["always", "Every time a value is shown, copied or used", "Browsing stays unlocked after the first check."],
                ["never", "Never", `Rely on your ${info.platform} sign-in alone. Agents with a shell could then read values with keylo get.`],
              ] as const).map(([mode, label, help]) => (
                <label key={mode} className="radio">
                  <input type="radio" name="hello" checked={draft.hello === mode} onChange={() => setDraft({ ...draft, hello: mode })} />
                  <span><strong>{label}</strong><small className="muted">{help}</small></span>
                </label>
              ))}
            </fieldset>
            <div className="form-grid">
              <label className="form-row">
                <span>Session length (minutes)</span>
                <input type="number" min={1} max={1440} value={draft.sessionMinutes}
                  onChange={(e) => setDraft({ ...draft, sessionMinutes: Number(e.target.value) })} disabled={draft.hello !== "session"} />
              </label>
              <label className="form-row">
                <span>Clear the clipboard after (seconds)</span>
                <input type="number" min={5} max={600} value={draft.clipboardSeconds}
                  onChange={(e) => setDraft({ ...draft, clipboardSeconds: Number(e.target.value) })} />
              </label>
              <label className="form-row">
                <span>Keep the activity log (days, 0 = forever)</span>
                <input type="number" min={0} max={3650} value={draft.auditRetentionDays}
                  onChange={(e) => setDraft({ ...draft, auditRetentionDays: Number(e.target.value) })} />
              </label>
            </div>
            <div className="form-actions">
              <button className="button" disabled={!dirty} onClick={() => setDraft(saved)}>Undo</button>
              <button className="button primary" disabled={!dirty} onClick={saveSettings}>Save</button>
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-header">
          <div>
            <h2>Access keys</h2>
            <p className="muted">
              A key lets an agent (such as Claude Code, through <code>keylo mcp</code>) run commands with the secrets it covers, without asking.
              Agents never see the values. Anything else asks you first.
            </p>
          </div>
          <button className="button primary" onClick={() => setKeyEditor("new")}><Plus size={16} /> New key</button>
        </div>
        {keys.length === 0 ? (
          <p className="muted empty-inline">No access keys yet.</p>
        ) : (
          <ul className="key-list">
            {keys.map((k) => (
              <li key={k.id} className="key-row">
                <KeyRound size={18} />
                <div className="key-text">
                  <strong>{k.name}</strong>
                  <span className="muted">
                    {k.scope === "all" ? "Every secret" : covers(k)} · created {timeAgo(k.created)}
                    {k.expired ? " · expired" : k.expires ? ` · expires ${new Date(k.expires).toLocaleDateString()}` : ""}
                  </span>
                </div>
                <button className="button small" onClick={() => setKeyEditor(k)}>Change</button>
                <button className="icon-button danger" onClick={() => revoke(k)} aria-label={`Revoke ${k.name}`} title="Revoke"><Trash2 size={16} /></button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <TypesSection types={props.types} secrets={props.secrets} run={run} onTypes={props.onTypes} />

      <VaultsSection run={run} verifierName={info.verifierName} />

      <BackupSection run={run} verifierName={info.verifierName} onRestored={props.onDataChanged} />

      <section className="card">
        <h2>About</h2>
        <dl className="about">
          <dt>Version</dt><dd>{info.version}</dd>
          <dt>Secrets</dt><dd>{info.storeName}</dd>
          <dt>Large values</dt><dd>{info.fileProtection}-encrypted files</dd>
          <dt>Data folder</dt><dd className="mono">{info.dataDir}</dd>
        </dl>
      </section>

      {keyEditor && (
        <KeyEditor
          existing={keyEditor === "new" ? null : keyEditor}
          categories={props.categories}
          secrets={props.secrets.map((s) => s.name)}
          run={run}
          onClose={() => setKeyEditor(null)}
          onSaved={(result) => {
            setKeyEditor(null);
            loadKeys();
            if (result) setToken(result);
            else toast("Key updated.");
          }}
        />
      )}

      {token && (
        <Modal title={`Key '${token.name}' created`} onClose={() => setToken(null)} wide
          footer={<button className="button primary" onClick={() => setToken(null)}>Done</button>}>
          <p>This is the only time the key is shown. To connect Claude Code, run this in a terminal:</p>
          <div className="code-line">
            <code>{claudeCommand(token.token)}</code>
            <button className="icon-button small" aria-label="Copy command"
              onClick={() => navigator.clipboard.writeText(claudeCommand(token.token)).then(() => toast("Copied."))}>
              <Copy size={15} />
            </button>
          </div>
          <p className="muted">Keep it in your user settings: never put it in a project's .mcp.json, where it could be committed.</p>
        </Modal>
      )}
    </main>
  );
}

function covers(k: AccessKey): string {
  const parts = [...k.categories.map((c) => `${c} (category)`), ...k.secrets];
  return parts.length ? parts.join(", ") : "Nothing yet (asks each time)";
}

function KeyEditor(props: {
  existing: AccessKey | null;
  categories: string[];
  secrets: string[];
  run: Run;
  onClose: () => void;
  onSaved: (created: { name: string; token: string } | null) => void;
}) {
  const e = props.existing;
  const [name, setName] = useState(e?.name ?? "Claude Code");
  const [scope, setScope] = useState(e?.scope ?? "selected");
  const [cats, setCats] = useState<string[]>(e?.categories ?? []);
  const [names, setNames] = useState<string[]>(e?.secrets ?? []);
  const [expires, setExpires] = useState<string>("");

  const toggle = (list: string[], set: (l: string[]) => void, v: string) =>
    set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  const save = async () => {
    const input: KeyInput = { name, scope, categories: cats, secrets: names, expiresDays: expires ? Number(expires) : null };
    if (e) {
      const ok = await props.run(async () => { await api.updateKey(e.id, input); return true; });
      if (ok) props.onSaved(null);
    } else {
      const token = await props.run(() => api.createKey(input));
      if (token) props.onSaved({ name, token });
    }
  };

  return (
    <Drawer title={e ? `Change ${e.name}` : "New access key"} onClose={props.onClose}
      dirty={!!e && (scope !== e.scope || JSON.stringify(cats) !== JSON.stringify(e.categories) || JSON.stringify(names) !== JSON.stringify(e.secrets))}
      footer={<>
        <button className="button" onClick={props.onClose}>Cancel</button>
        <button className="button primary" onClick={save} disabled={!name.trim()}>{e ? "Save" : "Create key"}</button>
      </>}>
      <div className="form">
        {!e && (
          <label className="form-row">
            <span>Name</span>
            <input value={name} onChange={(ev) => setName(ev.target.value)} />
          </label>
        )}
        <fieldset className="radio-group">
          <legend>It can use, without asking</legend>
          <label className="radio">
            <input type="radio" checked={scope === "selected"} onChange={() => setScope("selected")} />
            <span><strong>Selected categories and secrets</strong></span>
          </label>
          <label className="radio">
            <input type="radio" checked={scope === "all"} onChange={() => setScope("all")} />
            <span><strong>Every secret</strong></span>
          </label>
        </fieldset>
        {scope === "selected" && (
          <div className="pick-columns">
            <div>
              <h4>Categories</h4>
              {props.categories.length === 0 && <p className="muted">None yet.</p>}
              {props.categories.map((c) => (
                <label key={c} className="check"><input type="checkbox" checked={cats.includes(c)} onChange={() => toggle(cats, setCats, c)} /> {c}</label>
              ))}
            </div>
            <div>
              <h4>Secrets</h4>
              <div className="pick-scroll">
                {props.secrets.map((s) => (
                  <label key={s} className="check"><input type="checkbox" checked={names.includes(s)} onChange={() => toggle(names, setNames, s)} /> {s}</label>
                ))}
              </div>
            </div>
          </div>
        )}
        {!e && (
          <label className="form-row">
            <span>Expires after (days, empty = never)</span>
            <input type="number" min={1} value={expires} onChange={(ev) => setExpires(ev.target.value)} />
          </label>
        )}
      </div>
    </Drawer>
  );
}
