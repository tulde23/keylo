import { useState } from "react";
import { Check, Copy, Eye, EyeOff, Pencil, Pin, PinOff, Terminal, Trash2 } from "lucide-react";
import { api, timeAgo, type AppInfo, type CategorySummary, type Secret, type SecretType } from "../api";
import type { Run } from "../App";
import { Modal, SecretIcon, useToast } from "./ui";

interface Row {
  id: string;
  label: string;
  secret: boolean;
  multiline: boolean;
  url: boolean;
  /** Known without unlocking (non-secret fields). */
  value: string | null;
}

function rowsFor(secret: Secret, type: SecretType | undefined): Row[] {
  if (!type) {
    const rows: Row[] = [];
    if (secret.username) rows.push({ id: "username", label: "Username", secret: false, multiline: false, url: false, value: secret.username });
    rows.push({ id: "value", label: "Value", secret: true, multiline: true, url: false, value: null });
    return rows;
  }
  return type.fields
    .map((f) => ({
      id: f.id,
      label: f.label,
      secret: f.secret,
      multiline: f.kind === "SecretText",
      url: f.kind === "Url",
      value: f.secret ? null : f.kind === "Username" ? secret.username : secret.fields[f.id] ?? null,
    }))
    .filter((r) => r.secret || r.value);
}

export default function SecretDetail(props: {
  secret: Secret | null;
  type: SecretType | undefined;
  category: CategorySummary | undefined;
  info: AppInfo;
  run: Run;
  onEdit: (values: Record<string, string>) => void;
  onChanged: (selectName?: string | null) => Promise<void>;
}) {
  const { secret, type, run } = props;
  const toast = useToast();
  const [revealed, setRevealed] = useState<Record<string, string> | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (!secret) {
    return (
      <section className="detail-pane detail-empty">
        <p className="muted">Select a secret to see its details.</p>
      </section>
    );
  }

  const rows = rowsFor(secret, type);
  const variable = secret.name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_|_$/g, "") || "SECRET";
  const cliCommand = `keylo run --env ${variable}=${secret.name.includes(" ") ? `"${secret.name}"` : secret.name} -- YOUR-COMMAND`;

  const copy = async (field?: string) => {
    const seconds = await run(() => api.copy(secret.name, field));
    if (seconds !== undefined) {
      setCopied(field ?? "main");
      setTimeout(() => setCopied(null), 1500);
      toast(`Copied. The clipboard clears in ${seconds}s.`);
    }
  };

  const reveal = async () => {
    if (revealed) return setRevealed(null);
    const values = await run(() => api.reveal(secret.name));
    if (values) setRevealed(values);
  };

  const edit = async () => {
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
            <span className="chip">{secret.linked ? "Linked" : type?.name ?? "Secret"}</span>
            {secret.category && <span className="chip chip-soft">{secret.category}</span>}
          </div>
        </div>
      </header>

      <div className="toolbar">
        <button className="button primary" onClick={() => copy()} disabled={secret.linked}>
          {copied === "main" ? <Check size={16} /> : <Copy size={16} />} Copy {type?.fields.find((f) => f.main)?.label.toLowerCase() ?? "value"}
        </button>
        <button className="button" onClick={reveal} disabled={secret.linked}>
          {revealed ? <EyeOff size={16} /> : <Eye size={16} />} {revealed ? "Hide" : "Show"}
        </button>
        <button className="button" onClick={edit} disabled={secret.linked}><Pencil size={16} /> Edit</button>
        <span className="toolbar-gap" />
        <button className="icon-button" onClick={togglePin} title={secret.pinned ? "Unpin" : "Pin to Home"} aria-label={secret.pinned ? "Unpin" : "Pin"}>
          {secret.pinned ? <PinOff size={18} /> : <Pin size={18} />}
        </button>
        <button className="icon-button danger" onClick={() => setConfirmDelete(true)} title="Delete" aria-label="Delete">
          <Trash2 size={18} />
        </button>
      </div>

      {secret.linked && (
        <p className="notice">This secret is linked to another vault. Linked secrets aren't in the Rust build of Keylo yet; use them with the C# keylo.</p>
      )}

      <dl className="fields">
        {rows.map((r) => {
          const value = r.secret ? revealed?.[r.id] ?? null : r.value;
          return (
            <div className="field-row" key={r.id}>
              <dt>{r.label}</dt>
              <dd>
                {r.secret && value === null ? (
                  <span className="masked" aria-label="hidden">••••••••••••</span>
                ) : r.url && value ? (
                  <span className="field-value">{value}</span>
                ) : (
                  <span className={`field-value${r.multiline ? " multiline" : ""}${r.secret ? " mono" : ""}`}>{value ?? ""}</span>
                )}
                {!secret.linked && (
                  <button className="icon-button small" onClick={() => copy(r.id)} title={`Copy ${r.label.toLowerCase()}`} aria-label={`Copy ${r.label}`}>
                    {copied === r.id ? <Check size={15} /> : <Copy size={15} />}
                  </button>
                )}
              </dd>
            </div>
          );
        })}
        {secret.notes && (
          <div className="field-row">
            <dt>Notes</dt>
            <dd><span className="field-value multiline">{secret.notes}</span></dd>
          </div>
        )}
      </dl>

      <div className="use-box">
        <h3><Terminal size={15} /> Use it in a command</h3>
        <p className="muted">The value reaches the command as an environment variable and never appears on screen.</p>
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
        Updated {timeAgo(secret.updatedAt)} · {secret.fileBacked ? `stored as a ${props.info.fileProtection}-encrypted file` : `in ${props.info.storeName}`}
      </p>

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
          <p>It's removed from {props.info.storeName}. Commands and agents using it will stop working. This can't be undone.</p>
        </Modal>
      )}
    </section>
  );
}
