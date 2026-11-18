import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, Lock, Plus, Trash2 } from "lucide-react";
import { api, type FieldInput, type FieldKind, type Secret, type SecretType } from "../api";
import type { Run } from "../App";
import { ColorPicker, Drawer, IconPicker, IconTile, Modal, useToast } from "./ui";

const KINDS: { kind: FieldKind; label: string; help: string }[] = [
  { kind: "Text", label: "Text", help: "Shown without unlocking; searchable; agents with access can see it" },
  { kind: "Username", label: "Username", help: "The account or key id (one per type)" },
  { kind: "Url", label: "Web address", help: "Shown without unlocking" },
  { kind: "Number", label: "Number", help: "Shown without unlocking" },
  { kind: "Password", label: "Password", help: "Secret, one line" },
  { kind: "SecretText", label: "Secret text", help: "Secret, several lines (keys, certificates)" },
  { kind: "Totp", label: "One-time code", help: "A two-factor setup key; Keylo shows and copies its current code" },
];
const isSecret = (k: FieldKind) => k === "Password" || k === "SecretText" || k === "Totp";

/** Settings → Secret types: the built-in types (icon and colour only) and your own. */
export default function TypesSection({ types, secrets, run, onTypes }: {
  types: SecretType[];
  secrets: Secret[];
  run: Run;
  onTypes: (types: SecretType[]) => void;
}) {
  const toast = useToast();
  const [editing, setEditing] = useState<SecretType | "new" | null>(null);
  const [deleting, setDeleting] = useState<SecretType | null>(null);
  const uses = (t: SecretType) => secrets.filter((s) => s.type === t.id).length;

  const remove = async (t: SecretType) => {
    setDeleting(null);
    const updated = await run(() => api.deleteType(t.id));
    if (updated) {
      onTypes(updated);
      toast(`Deleted the type '${t.name}'.`);
    }
  };

  return (
    <section className="card">
      <div className="card-header">
        <div>
          <h2>Secret types</h2>
          <p className="muted">Types give secrets named fields. Secret fields are encrypted; the others show without unlocking and can be searched.</p>
        </div>
        <button className="button primary" onClick={() => setEditing("new")}><Plus size={16} /> New type</button>
      </div>
      <ul className="key-list">
        {types.map((t) => {
          const n = uses(t);
          return (
            <li key={t.id} className="key-row">
              <IconTile icon={t.icon} color={t.color} size={32} />
              <div className="key-text">
                <strong>{t.name} {t.builtIn && <span className="chip chip-soft">Built-in</span>}</strong>
                <span className="muted">
                  {t.fields.map((f) => f.label).join(" · ")}{n > 0 ? ` · ${n} secret${n === 1 ? "" : "s"}` : ""}
                </span>
              </div>
              <button className="button small" onClick={() => setEditing(t)}>{t.builtIn ? "Style" : "Edit"}</button>
              {!t.builtIn && (
                <button className="icon-button danger" onClick={() => setDeleting(t)} aria-label={`Delete ${t.name}`} title="Delete">
                  <Trash2 size={16} />
                </button>
              )}
            </li>
          );
        })}
      </ul>

      {editing && (
        <TypeEditor
          type={editing === "new" ? null : editing}
          inUse={editing === "new" ? 0 : uses(editing)}
          run={run}
          onClose={() => setEditing(null)}
          onSaved={(updated, name) => {
            setEditing(null);
            onTypes(updated);
            toast(`Saved the type '${name}'.`);
          }}
        />
      )}

      {deleting && (
        <Modal
          title={`Delete the type '${deleting.name}'?`}
          onClose={() => setDeleting(null)}
          footer={uses(deleting) > 0 ? (
            <button className="button primary" onClick={() => setDeleting(null)}>OK</button>
          ) : (
            <>
              <button className="button" onClick={() => setDeleting(null)}>Cancel</button>
              <button className="button danger-fill" onClick={() => remove(deleting)}>Delete</button>
            </>
          )}
        >
          {uses(deleting) > 0
            ? <p>{uses(deleting) === 1 ? "1 secret uses it. Change its type, or delete it, first." : `${uses(deleting)} secrets use it. Change their type, or delete them, first.`}</p>
            : <p>No secrets use it. This can't be undone.</p>}
        </Modal>
      )}
    </section>
  );
}

function TypeEditor({ type, inUse, run, onClose, onSaved }: {
  type: SecretType | null;
  inUse: number;
  run: Run;
  onClose: () => void;
  onSaved: (types: SecretType[], name: string) => void;
}) {
  const builtIn = !!type?.builtIn;
  const [name, setName] = useState(type?.name ?? "");
  const [icon, setIcon] = useState<string | null>(type?.icon ?? "Apps24");
  const [color, setColor] = useState<string | null>(type?.color ?? null);
  const [fields, setFields] = useState<FieldInput[]>(() =>
    type?.fields.map((f) => ({ id: f.id, label: f.label, kind: f.kind, options: f.options })) ?? [
      { id: "", label: "Username", kind: "Username", options: null },
      { id: "", label: "Secret", kind: "Password", options: null },
    ]);
  const [busy, setBusy] = useState(false);

  const initial = useMemo(() => JSON.stringify([type?.name ?? "", type?.icon ?? "Apps24", type?.color ?? null,
    type?.fields.map((f) => ({ id: f.id, label: f.label, kind: f.kind, options: f.options })) ?? null]), [type]);
  const dirty = JSON.stringify([name, icon, color, type ? fields : null]) !== initial || (!type && name !== "");

  // The same checks the backend makes, shown as you type.
  const problem = builtIn ? null
    : !name.trim() ? "Give the type a name."
    : fields.length === 0 ? "Add at least one field."
    : !fields.some((f) => isSecret(f.kind)) ? "Add at least one secret field (Password or Secret text)."
    : fields.filter((f) => f.kind === "Username").length > 1 ? "Only one field can be the Username."
    : fields.some((f) => !f.label.trim()) ? "Every field needs a label."
    : null;
  const mainIndex = fields.findIndex((f) => isSecret(f.kind));

  const update = (i: number, change: Partial<FieldInput>) =>
    setFields((list) => list.map((f, j) => (j === i ? { ...f, ...change } : f)));
  const move = (i: number, by: number) =>
    setFields((list) => {
      const next = [...list];
      [next[i], next[i + by]] = [next[i + by], next[i]];
      return next;
    });

  const save = async () => {
    setBusy(true);
    const updated = await run(() => api.saveType(type?.id ?? null, { name: name.trim(), icon, color, fields }));
    setBusy(false);
    if (updated) onSaved(updated, name.trim());
  };

  return (
    <Drawer
      title={type ? `${builtIn ? "Style" : "Edit"} ${type.name}` : "New secret type"}
      onClose={onClose}
      dirty={dirty && !busy}
      footer={<>
        {problem && <span className="drawer-problem">{problem}</span>}
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" onClick={save} disabled={!!problem || busy || !dirty}>{type ? "Save" : "Add type"}</button>
      </>}
    >
      <div className="form">
        {!builtIn && (
          <label className="form-row">
            <span>Name</span>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Wi-Fi network, Credit card…" />
          </label>
        )}

        <div className="form-row">
          <span>Icon</span>
          <IconPicker value={icon} onChange={(i) => setIcon(i ?? "Apps24")} />
        </div>

        <div className="form-row">
          <span>Colour</span>
          <ColorPicker value={color} onChange={setColor} />
        </div>

        <div className="form-row">
          <span>Fields</span>
          {builtIn ? (
            <p className="muted">Built-in types keep their fields: {type!.fields.map((f) => f.label).join(", ")}.</p>
          ) : (
            <>
              {inUse > 0 && (
                <p className="muted small-text">
                  {inUse} secret{inUse === 1 ? " uses" : "s use"} this type. Renaming a field keeps its data; removing one hides it.
                </p>
              )}
              <ol className="field-editor">
                {fields.map((f, i) => (
                  <li key={i} className="field-edit-row">
                    <div className="field-edit-main">
                      <input value={f.label} onChange={(e) => update(i, { label: e.target.value })} aria-label="Field label" placeholder="Label" />
                      <select value={f.kind} onChange={(e) => update(i, { kind: e.target.value as FieldKind })} aria-label="Field kind"
                        title={KINDS.find((k) => k.kind === f.kind)?.help}>
                        {KINDS.map((k) => <option key={k.kind} value={k.kind}>{k.label}</option>)}
                      </select>
                      <button type="button" className="icon-button small" onClick={() => move(i, -1)} disabled={i === 0} aria-label="Move up"><ArrowUp size={15} /></button>
                      <button type="button" className="icon-button small" onClick={() => move(i, 1)} disabled={i === fields.length - 1} aria-label="Move down"><ArrowDown size={15} /></button>
                      <button type="button" className="icon-button small danger" onClick={() => setFields((l) => l.filter((_, j) => j !== i))} aria-label="Remove field"><Trash2 size={15} /></button>
                    </div>
                    <div className="field-edit-sub">
                      {isSecret(f.kind) ? (
                        <span className="muted small-text"><Lock size={12} /> Secret{i === mainIndex ? " · the main value (copied and used by default)" : ""}</span>
                      ) : f.kind === "Text" ? (
                        <input className="small-input" value={(f.options ?? []).join(", ")} placeholder="Suggestions, comma-separated (optional)"
                          onChange={(e) => update(i, { options: e.target.value ? e.target.value.split(",").map((o) => o.trimStart()) : null })} />
                      ) : (
                        <span className="muted small-text">{KINDS.find((k) => k.kind === f.kind)?.help}</span>
                      )}
                    </div>
                  </li>
                ))}
              </ol>
              <button type="button" className="button small add-field"
                onClick={() => setFields((l) => [...l, { id: "", label: `Field ${l.length + 1}`, kind: "Text", options: null }])}>
                <Plus size={15} /> Add field
              </button>
            </>
          )}
        </div>
      </div>
    </Drawer>
  );
}
