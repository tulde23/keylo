import { useEffect, useState } from "react";
import { Check, Copy, Eye, EyeOff, Link2, Pencil, Pin, PinOff, Send, Terminal, Trash2 } from "lucide-react";
import { api, timeAgo, type AppInfo, type CategorySummary, type PushPreview, type Secret, type SecretType, type VaultProvider } from "../api";
import type { Run } from "../App";
import { Modal, SecretIcon, useToast } from "./ui";

interface Row {
  id: string;
  label: string;
  secret: boolean;
  multiline: boolean;
  url: boolean;
  /** A one-time code field: shows the current code with a countdown. */
  otp: boolean;
  /** Known without unlocking (non-secret fields of Keylo's own secrets). */
  value: string | null;
}

function rowsFor(secret: Secret, type: SecretType | undefined): Row[] {
  // A link's fields live in its vault: every value is read from there when shown.
  if (secret.link) {
    return secret.link.fields.map((f) => ({
      id: f.id, label: f.label, secret: f.secret, multiline: f.id === "notes", url: f.id.startsWith("website") || f.id.includes("url"), otp: false, value: null,
    }));
  }
  if (!type) {
    const rows: Row[] = [];
    if (secret.username) rows.push({ id: "username", label: "Username", secret: false, multiline: false, url: false, otp: false, value: secret.username });
    rows.push({ id: "value", label: "Value", secret: true, multiline: true, url: false, otp: false, value: null });
    return rows;
  }
  return type.fields
    .map((f) => ({
      id: f.id,
      label: f.label,
      secret: f.secret,
      multiline: f.kind === "SecretText",
      url: f.kind === "Url",
      otp: f.kind === "Totp",
      value: f.secret ? null : f.kind === "Username" ? secret.username : secret.fields[f.id] ?? null,
    }))
    // One-time code fields only when set (a visible marker says so; the key stays encrypted).
    .filter((r) => (r.otp ? !!secret.fields[r.id] : r.secret || r.value));
}

export default function SecretDetail(props: {
  secret: Secret | null;
  type: SecretType | undefined;
  category: CategorySummary | undefined;
  info: AppInfo;
  run: Run;
  onEdit: (values: Record<string, string>) => void;
  onChanged: (selectName?: string | null) => Promise<void>;
  /** Keep a shown one-time code current (not when every use asks for the identity check). */
  autoRefreshCodes: boolean;
}) {
  const { secret, type, run } = props;
  const toast = useToast();
  const link = secret?.link ?? null;
  const [revealed, setRevealed] = useState<Record<string, string> | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [environment, setEnvironment] = useState<string | null>(link?.defaultEnvironment ?? null);
  const [reading, setReading] = useState(false);
  const [providers, setProviders] = useState<VaultProvider[]>([]);
  const [pushing, setPushing] = useState<VaultProvider | null>(null);

  // Vaults this secret can be pushed to (set up in Settings → Vault providers).
  useEffect(() => {
    if (!secret || secret.linked) return;
    api.vaultProviders().then((p) => setProviders(p.filter((x) => x.pushConfigured))).catch(() => {});
  }, [secret]);

  if (!secret) {
    return (
      <section className="detail-pane detail-empty">
        <div className="empty-state">
          <img src="/keylo.svg" alt="" width={72} height={72} />
          <h2>Select a secret</h2>
          <p className="muted">Values stay encrypted until you reveal or copy them.</p>
          <p className="muted">Ctrl+N new · Ctrl+F search · Ctrl+L lock</p>
        </div>
      </section>
    );
  }

  const rows = rowsFor(secret, type);
  const env = link?.perEnvironment ? environment : null;
  const reference = `${secret.name}${env && env !== link?.defaultEnvironment ? `@${env}` : ""}`;
  const variable = secret.name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_|_$/g, "") || "SECRET";
  const cliCommand = `keylo run --env ${variable}=${reference.includes(" ") ? `"${reference}"` : reference} -- YOUR-COMMAND`;
  const mainLabel = link
    ? link.fields.find((f) => f.id === link.mainField)?.label.toLowerCase() ?? "value"
    : type?.fields.find((f) => f.main)?.label.toLowerCase() ?? "value";

  const copy = async (field?: string) => {
    setReading(!!link);
    const seconds = await run(() => api.copy(secret.name, field, env));
    setReading(false);
    if (seconds !== undefined) {
      setCopied(field ?? "main");
      setTimeout(() => setCopied(null), 1500);
      toast(`Copied. The clipboard clears in ${seconds}s.`);
    }
  };

  const reveal = async () => {
    if (revealed) return setRevealed(null);
    setReading(!!link);
    const values = await run(() => api.reveal(secret.name, false, env));
    setReading(false);
    if (values) setRevealed(values);
  };

  const edit = async () => {
    // A link's details only: its values stay in the vault.
    if (secret.linked) return props.onEdit({});
    const values = await run(() => api.reveal(secret.name, true));
    if (values) props.onEdit(values);
  };

  const togglePin = async () => {
    await run(() => api.setPinned(secret.name, !secret.pinned));
    await props.onChanged();
  };

  const remove = async () => {
    setConfirmDelete(false);
    const done = await run(async () => { await api.remove(secret.name); return true; });
    if (done) {
      toast(`Deleted '${secret.name}'.`);
      await props.onChanged(null);
    }
  };

  return (
    <section className="detail-pane" aria-label={secret.name}>
      <header className="detail-header">
        <SecretIcon secret={secret} type={type} category={props.category} size={48} />
        <div className="detail-title">
          <h1>{secret.name}</h1>
          <div className="chips">
            <span className="chip">{link ? `Linked · ${link.providerName}` : type?.name ?? "Secret"}</span>
            {link?.perEnvironment && <span className="chip chip-soft">per environment</span>}
            {secret.category && <span className="chip chip-soft">{secret.category}</span>}
          </div>
        </div>
      </header>

      <div className="toolbar">
        <button className="button primary" onClick={() => copy()} disabled={reading}>
          {copied === "main" ? <Check size={16} /> : <Copy size={16} />} Copy {mainLabel}
        </button>
        <button className="button" onClick={reveal} disabled={reading}>
          {revealed ? <EyeOff size={16} /> : <Eye size={16} />} {revealed ? "Hide" : "Show"}
        </button>
        <button className="button" onClick={edit}><Pencil size={16} /> Edit</button>
        {providers.length > 0 && (
          providers.length === 1 ? (
            <button className="button" onClick={() => setPushing(providers[0])} title={`Copy it into ${providers[0].name}`}>
              <Send size={16} /> Push to {providers[0].name}
            </button>
          ) : (
            <select className="button" value="" aria-label="Push to another vault"
              onChange={(e) => setPushing(providers.find((p) => p.id === e.target.value) ?? null)}>
              <option value="" disabled>Push to…</option>
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )
        )}
        <span className="toolbar-gap" />
        <button className="icon-button" onClick={togglePin} title={secret.pinned ? "Unpin" : "Pin to Home"} aria-label={secret.pinned ? "Unpin" : "Pin"}>
          {secret.pinned ? <PinOff size={18} /> : <Pin size={18} />}
        </button>
        <button className="icon-button danger" onClick={() => setConfirmDelete(true)} title="Delete" aria-label="Delete">
          <Trash2 size={18} />
        </button>
      </div>

      {link && (
        <div className="link-box">
          <Link2 size={16} />
          <div>
            <div>
              Linked to <strong>{link.title}</strong> in {link.providerName}
              {link.where && !link.perEnvironment && <span className="muted"> · {link.where}</span>}
            </div>
            <div className="muted small-text">
              {link.perEnvironment
                ? "Read from the chosen environment's account each time it's used; nothing is copied into Keylo."
                : "Read from there each time it's used; nothing is copied into Keylo."}
            </div>
            {link.perEnvironment && (
              link.environments.length === 0 ? (
                <div className="warning small-text">No environments yet: add them in Settings → Vault providers.</div>
              ) : (
                <div className="env-picker" role="radiogroup" aria-label="Environment">
                  {link.environments.map((e) => (
                    <button key={e.name} role="radio" aria-checked={environment === e.name}
                      className={`chip-button${environment === e.name ? " active" : ""}`}
                      onClick={() => { setEnvironment(e.name); setRevealed(null); }}
                      title={[e.profile ?? "default credentials", e.region, e.alwaysAsk ? "agents always ask" : null].filter(Boolean).join(" · ")}>
                      {e.name}{e.name === link.defaultEnvironment && <span className="muted"> · default</span>}
                      {e.alwaysAsk && <span className="ask-dot" aria-label="always asks" />}
                    </button>
                  ))}
                </div>
              )
            )}
          </div>
        </div>
      )}
      {reading && <p className="muted small-text">Waiting for {link?.providerName ?? "the vault"}… approve it if it asks.</p>}

      <dl className="fields">
        {rows.map((r) => {
          if (r.otp) return <OtpRow key={r.id} name={secret.name} field={r.id} label={r.label} run={run}
            copied={copied === r.id} onCopy={() => copy(r.id)} autoRefresh={props.autoRefreshCodes} />;
          const value = r.secret || link ? revealed?.[r.id] ?? null : r.value;
          return (
            <div className="field-row" key={r.id}>
              <dt>{r.label}</dt>
              <dd>
                {value === null ? (
                  <span className="masked" aria-label="hidden">{r.secret ? "••••••••••••" : "—"}</span>
                ) : (
                  <span className={`field-value${r.multiline ? " multiline" : ""}${r.secret ? " mono" : ""}`}>{value}</span>
                )}
                <button className="icon-button small" onClick={() => copy(r.id)} disabled={reading} title={`Copy ${r.label.toLowerCase()}`} aria-label={`Copy ${r.label}`}>
                  {copied === r.id ? <Check size={15} /> : <Copy size={15} />}
                </button>
              </dd>
            </div>
          );
        })}
        {link && revealed && Object.keys(revealed).filter((k) => !rows.some((r) => r.id === k)).map((k) => (
          // Fields added to the item since it was linked.
          <div className="field-row" key={k}>
            <dt>{k}</dt>
            <dd><span className="field-value mono">{revealed[k]}</span></dd>
          </div>
        ))}
        {secret.notes && (
          <div className="field-row">
            <dt>Notes</dt>
            <dd><span className="field-value multiline">{secret.notes}</span></dd>
          </div>
        )}
      </dl>

      <div className="use-box">
        <h3><Terminal size={15} /> Use it in a command</h3>
        <p className="muted">
          The value reaches the command as an environment variable and never appears on screen.
          {link?.perEnvironment && " Add @ENV to the name for another environment."}
        </p>
        <div className="code-line">
          <code>{cliCommand}</code>
          <button
            className="icon-button small"
            aria-label="Copy command"
            onClick={() => navigator.clipboard.writeText(cliCommand).then(() => toast("Command copied."))}
          >
            <Copy size={15} />
          </button>
        </div>
      </div>

      <p className="meta">
        Updated {timeAgo(secret.updatedAt)} ·{" "}
        {link ? `a link; values stay in ${link.providerName}` : secret.fileBacked ? `stored as a ${props.info.fileProtection}-encrypted file` : `in ${props.info.storeName}`}
      </p>

      {pushing && <PushDialog provider={pushing} name={secret.name} run={run} onClose={() => setPushing(null)} />}

      {confirmDelete && (
        <Modal
          title={`Delete '${secret.name}'?`}
          onClose={() => setConfirmDelete(false)}
          footer={
            <>
              <button className="button" onClick={() => setConfirmDelete(false)}>Cancel</button>
              <button className="button danger-fill" onClick={remove} autoFocus>Delete</button>
            </>
          }
        >
          {link
            ? <p>Only the link is removed; {link.title} stays in {link.providerName}. Commands and agents using '{secret.name}' will stop working.</p>
            : <p>It's removed from {props.info.storeName}. Commands and agents using it will stop working. This can't be undone.</p>}
        </Modal>
      )}
    </section>
  );
}

/** Confirms a push: where it goes, and whether it creates an item or updates the one pushed before. */
function PushDialog({ provider, name, run, onClose }: { provider: VaultProvider; name: string; run: Run; onClose: () => void }) {
  const toast = useToast();
  const [preview, setPreview] = useState<PushPreview | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let current = true;
    run(() => api.pushPreview(provider.id, name)).then((p) => current && p && setPreview(p));
    return () => { current = false; };
  }, [provider, name, run]);

  const push = async () => {
    setBusy(true);
    const result = await run(() => api.pushSecret(provider.id, name));
    setBusy(false);
    if (!result) return;
    toast(result.succeeded ? `${result.message}.` : result.message, !result.succeeded);
    if (result.succeeded) onClose();
  };

  return (
    <Modal title={`Push to ${provider.name}`} onClose={onClose}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={!preview || busy} onClick={push}>
          {busy ? "Pushing…" : preview?.exists ? "Update" : "Push"}
        </button>
      </>}>
      {!preview ? (
        <p className="muted">Checking {provider.name}…</p>
      ) : (
        <>
          <p>Copies <strong>{name}</strong> to {preview.target}.</p>
          <p className={preview.exists ? "warning" : "muted"}>
            {preview.exists === true
              ? `Updates the “${name}” item Keylo pushed there before.`
              : preview.exists === false
                ? "Creates a new item, tagged as Keylo's."
                : "Creates the item, or updates the one Keylo pushed before."}
          </p>
          <p className="muted small-text">The copy there is separate: later changes in Keylo need another push.</p>
        </>
      )}
    </Modal>
  );
}

/**
 * A one-time code: hidden until shown, then the current code with a countdown, kept current while
 * shown (when the identity check allows it without asking each time).
 */
function OtpRow({ name, field, label, run, copied, onCopy, autoRefresh }: {
  name: string;
  field: string;
  label: string;
  run: Run;
  copied: boolean;
  onCopy: () => void;
  autoRefresh: boolean;
}) {
  const [code, setCode] = useState<{ code: string; until: number; period: number } | null>(null);
  const [now, setNow] = useState(Date.now());

  const load = async () => {
    const c = await run(() => api.otpCode(name, field));
    if (c) setCode({ code: c.code, until: Date.now() + c.secondsLeft * 1000, period: c.period });
  };

  useEffect(() => {
    if (!code) return;
    const tick = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(tick);
  }, [code]);

  const left = code ? Math.max(0, Math.ceil((code.until - now) / 1000)) : 0;
  useEffect(() => {
    if (code && left === 0) {
      if (autoRefresh) load();
      else setCode(null);
    }
  }, [left]); // eslint-disable-line react-hooks/exhaustive-deps

  const pretty = code ? (code.code.length === 6 ? `${code.code.slice(0, 3)} ${code.code.slice(3)}` : code.code) : "";
  return (
    <div className="field-row">
      <dt>{label}</dt>
      <dd>
        {code ? (
          <span className="field-value otp-value">
            <span className="mono otp-code">{pretty}</span>
            <span className={`otp-timer${left <= 5 ? " ending" : ""}`} title={`Changes in ${left}s`}
              style={{ ["--otp-left" as string]: `${(left / code.period) * 100}%` }}>{left}</span>
          </span>
        ) : (
          <button className="button small" onClick={load}>Show code</button>
        )}
        <button className="icon-button small" onClick={onCopy} title="Copy the current code" aria-label={`Copy ${label}`}>
          {copied ? <Check size={15} /> : <Copy size={15} />}
        </button>
      </dd>
    </div>
  );
}
