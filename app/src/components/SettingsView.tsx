import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Bot, Folder, FolderSync, Search, Copy, Info, KeyRound, Link2, Palette, Plus, Settings2, Shapes, ShieldCheck, Trash2, X, type LucideIcon } from "lucide-react";
import { api, message, timeAgo, type CategorySummary, type ClaudeStatus, type AccessKey, type AppInfo, type KeyInput, type Secret, type SecretType, type Settings } from "../api";
import TypesSection from "./TypesSection";
import BackupSection from "./BackupSection";
import SyncSection from "./SyncSection";
import VaultsSection from "./VaultsSection";
import AppearanceSection from "./AppearanceSection";
import { autoCheck, setAutoCheck, SHOW_UPDATE } from "./UpdateNotice";
import type { Run } from "../App";
import { Drawer, IconTile, Modal, SecretIcon, useToast } from "./ui";

type Tab = "general" | "appearance" | "agents" | "types" | "vaults" | "sync" | "backup" | "about";

const TABS: { id: Tab; label: string; icon: LucideIcon }[] = [
  { id: "general", label: "General", icon: Settings2 },
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "agents", label: "Agents", icon: Bot },
  { id: "types", label: "Secret types", icon: Shapes },
  { id: "vaults", label: "Vault providers", icon: Link2 },
  { id: "sync", label: "Sync", icon: FolderSync },
  { id: "backup", label: "Backup", icon: ShieldCheck },
  { id: "about", label: "About", icon: Info },
];

/**
 * Settings, as a dialog with a tab for each area (as in the C# app). Esc or a click outside closes
 * it; drawers and dialogs opened from it (key editor, new key) sit on top and close first.
 */
export default function SettingsView(props: {
  info: AppInfo;
  secrets: Secret[];
  types: SecretType[];
  onTypes: (types: SecretType[]) => void;
  categories: CategorySummary[];
  run: Run;
  onSettingsSaved: () => Promise<void>;
  onDataChanged: () => void;
  onClose: () => void;
  /** Bumped when Keylo's data changed outside the window: keys, settings and Claude Code's status reload. */
  version: number;
}) {
  const { info, run, onClose } = props;
  const [tab, setTab] = useState<Tab>("general");
  const toast = useToast();
  const [saved, setSaved] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [keys, setKeys] = useState<AccessKey[]>([]);
  const [keyEditor, setKeyEditor] = useState<AccessKey | "new" | null>(null);
  const [token, setToken] = useState<{ name: string; token: string } | null>(null);
  const [claude, setClaude] = useState<ClaudeStatus | null>(null);
  const [adding, setAdding] = useState(false);
  const loadClaude = () => api.claudeStatus().then(setClaude).catch(() => {});

  const loadKeys = () => run(api.keys).then((k) => k && setKeys(k));
  useEffect(() => {
    run(api.settings).then((s) => { if (s) { setSaved(s); setDraft(s); } });
    loadKeys();
    loadClaude();
  }, []);

  const dirty = saved && draft && JSON.stringify(saved) !== JSON.stringify(draft);

  // Changed outside the window (keylo keys create, keylo config…): reload, keeping unsaved edits.
  const dirtyNow = useRef(false);
  dirtyNow.current = !!dirty;
  useEffect(() => {
    if (props.version === 0) return;
    api.keys().then(setKeys).catch(() => {});
    loadClaude();
    api.settings().then((s) => { if (!dirtyNow.current) { setSaved(s); setDraft(s); } }).catch(() => {});
  }, [props.version]); // eslint-disable-line react-hooks/exhaustive-deps
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

  // Esc closes Settings, unless a drawer or dialog opened from it is showing (that closes first).
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !document.querySelector(".drawer-backdrop, .modal-backdrop")) onClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);

  const claudeCommand = (t: string) =>
    `claude mcp add keylo --scope user --env KEYLO_ACCESS_KEY=${t} -- "${info.keyloPath}" mcp`;

  return createPortal(
    <div className="settings-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
    <div className="settings-dialog" role="dialog" aria-modal="true" aria-label="Settings">
      <nav className="settings-tabs" role="tablist" aria-orientation="vertical" aria-label="Settings sections">
        <h2>Settings</h2>
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={tab === t.id} className={`settings-tab${tab === t.id ? " active" : ""}`}
            onClick={() => setTab(t.id)}>
            <t.icon size={16} /> {t.label}
          </button>
        ))}
      </nav>
      <div className="settings-main">
      <header className="settings-header">
        <h1>{TABS.find((t) => t.id === tab)?.label}</h1>
        <button className="icon-button" onClick={onClose} aria-label="Close settings" title="Close (Esc)"><X size={18} /></button>
      </header>
      <div className="settings-content" role="tabpanel" aria-label={TABS.find((t) => t.id === tab)?.label}>

      {tab === "general" && (
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
      )}

      {tab === "appearance" && <AppearanceSection run={run} />}

      {tab === "agents" && (
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
        {claude && (
          <p className={`claude-status ${claude.registered && claude.keyName && claude.pointsAt ? "ok" : "muted"}`}>
            <strong>Claude Code:</strong> {claude.summary}
            {claude.keyCovers && ` (${claude.keyCovers}, run only)`}.
            {!(claude.registered && claude.keyName) && " Create a key below and choose Add to Claude Code."}
          </p>
        )}
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
      )}

      {tab === "types" && <TypesSection types={props.types} secrets={props.secrets} run={run} onTypes={props.onTypes} />}

      {tab === "vaults" && <VaultsSection run={run} verifierName={info.verifierName} />}

      {tab === "sync" && <SyncSection run={run} verifierName={info.verifierName} />}

      {tab === "backup" && <BackupSection run={run} verifierName={info.verifierName} onRestored={props.onDataChanged} />}

      {tab === "about" && (
      <section className="card">
        <h2>About</h2>
        <dl className="about">
          <dt>Version</dt><dd>{info.version}</dd>
          <dt>Secrets</dt><dd>{info.storeName}</dd>
          <dt>Large values</dt><dd>{info.fileProtection}-encrypted files</dd>
          <dt>Data folder</dt><dd className="mono">{info.dataDir}</dd>
        </dl>
        <UpdatesRow />
      </section>
      )}
      </div>
      </div>
    </div>

      {keyEditor && (
        <KeyEditor
          existing={keyEditor === "new" ? null : keyEditor}
          categories={props.categories}
          secrets={props.secrets}
          types={props.types}
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
          <p>This is the only time the key is shown.</p>
          <div className="form-actions start">
            <button className="button primary" disabled={adding || claude?.cliInstalled === false}
              title={claude?.cliInstalled === false ? "Claude Code ('claude') wasn't found on PATH." : undefined}
              onClick={async () => {
                setAdding(true);
                const done = await run(async () => { await api.addToClaude(token.token); return true; });
                setAdding(false);
                if (done) {
                  toast("Added. Restart Claude Code (or run /mcp) to load the Keylo tools.");
                  loadClaude();
                  setToken(null);
                }
              }}>
              {adding ? "Adding…" : "Add to Claude Code"}
            </button>
            <span className="muted small-text">Replaces any Keylo server Claude Code has (user scope).</span>
          </div>
          <p>Or run this in a terminal:</p>
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
    </div>,
    document.body,
  );
}

function covers(k: AccessKey): string {
  const parts = [...k.categories.map((c) => `${c} (category)`), ...k.secrets];
  return parts.length ? parts.join(", ") : "Nothing yet (asks each time)";
}

function KeyEditor(props: {
  existing: AccessKey | null;
  categories: CategorySummary[];
  secrets: Secret[];
  types: SecretType[];
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
  const [query, setQuery] = useState("");

  const same = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" }) === 0;
  const toggle = (list: string[], set: (l: string[]) => void, v: string) =>
    set(list.some((x) => same(x, v)) ? list.filter((x) => !same(x, v)) : [...list, v]);
  // What the key covers, as Keylo decides it: a chosen category, or the secret by name.
  const viaCategory = (s: Secret) => (s.category ? cats.find((c) => same(c, s.category!)) : undefined);
  const covered = props.secrets.filter((s) => viaCategory(s) || names.some((n) => same(n, s.name)));
  const shown = props.secrets.filter((s) => {
    const q = query.trim().toLowerCase();
    return !q || s.name.toLowerCase().includes(q) || (s.category ?? "").toLowerCase().includes(q);
  });
  const typeOf = (s: Secret) => props.types.find((t) => t.id === s.type);
  const categoryOf = (s: Secret) => props.categories.find((c) => s.category && same(c.name, s.category));

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
            <span><strong>Selected categories and secrets</strong><small className="muted">Anything else asks you first.</small></span>
          </label>
          <label className="radio">
            <input type="radio" checked={scope === "all"} onChange={() => setScope("all")} />
            <span><strong>Every secret</strong><small className="muted">Including ones added later.</small></span>
          </label>
        </fieldset>

        {scope === "selected" && (
          <>
            <p className="scope-summary">
              Covers <strong>{covered.length}</strong> of {props.secrets.length} secret{props.secrets.length === 1 ? "" : "s"} without asking.
            </p>

            <div className="scope-section">
              <div className="scope-head">
                <h4>Categories</h4>
                <span className="muted small-text">Every secret in them, including ones added later</span>
              </div>
              {props.categories.length === 0 ? <p className="muted small-text">No categories yet.</p> : (
                <ul className="pick-list">
                  {props.categories.map((c) => {
                    const on = cats.some((x) => same(x, c.name));
                    return (
                      <li key={c.name}>
                        <label className={`pick-row${on ? " on" : ""}`}>
                          <input type="checkbox" checked={on} onChange={() => toggle(cats, setCats, c.name)} />
                          <IconTile icon={c.icon} color={c.color} size={22} fallback={Folder} />
                          <span className="pick-name">{c.name}</span>
                          <small className="muted">{c.count} secret{c.count === 1 ? "" : "s"}</small>
                        </label>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            <div className="scope-section">
              <div className="scope-head">
                <h4>Secrets</h4>
                <span className="muted small-text">One by one</span>
              </div>
              <div className="pick-search">
                <Search size={14} className="muted" />
                <input value={query} onChange={(ev) => setQuery(ev.target.value)} placeholder="Filter secrets" aria-label="Filter secrets" spellCheck={false} />
              </div>
              <ul className="pick-list scroll">
                {shown.map((s) => {
                  const via = viaCategory(s);
                  const on = !!via || names.some((n) => same(n, s.name));
                  return (
                    <li key={s.name}>
                      <label className={`pick-row${on ? " on" : ""}${via ? " via" : ""}`} title={via ? `Included through the ${via} category` : undefined}>
                        <input type="checkbox" checked={on} disabled={!!via} onChange={() => toggle(names, setNames, s.name)} />
                        <SecretIcon secret={s} type={typeOf(s)} category={categoryOf(s)} size={22} />
                        <span className="pick-name">{s.name}</span>
                        {via ? <small className="pick-via">via {via}</small> : s.category && <small className="muted">{s.category}</small>}
                      </label>
                    </li>
                  );
                })}
                {shown.length === 0 && <li className="muted small-text pick-empty">No secrets match.</li>}
              </ul>
            </div>
          </>
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

/** Settings → About: check now, and whether Keylo checks by itself. */
function UpdatesRow() {
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [auto, setAuto] = useState(autoCheck());
  const check = async () => {
    setChecking(true);
    setResult(null);
    try {
      const u = await api.checkUpdate();
      if (u.available) {
        setResult(`Keylo ${u.latest} is available.`);
        window.dispatchEvent(new CustomEvent(SHOW_UPDATE, { detail: u }));
      } else {
        setResult(`Keylo is up to date (${u.current}).`);
      }
    } catch (e) {
      setResult(message(e));
    }
    setChecking(false);
  };
  return (
    <div className="about-updates">
      <div className="form-actions start">
        <button className="button" onClick={check} disabled={checking}>{checking ? "Checking…" : "Check for updates"}</button>
        {result && <span className="muted">{result}</span>}
      </div>
      <label>
        <input type="checkbox" checked={auto} onChange={(e) => { setAuto(e.target.checked); setAutoCheck(e.target.checked); }} />
        Check for updates automatically (asks before installing)
      </label>
    </div>
  );
}
