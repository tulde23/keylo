import { useMemo, useState } from "react";
import { Eye, EyeOff, Wand2 } from "lucide-react";
import { api, type CategorySummary, type Secret, type SecretType } from "../api";
import type { Run } from "../App";
import CategoryPicker from "./CategoryPicker";
import { ColorPicker, Drawer, IconPicker, iconFor, SecretIcon } from "./ui";

const PLAIN = "";

/** Adds or edits a secret. `values` are the revealed fields of the secret being edited. */
export default function SecretEditor(props: {
  secret: Secret | null;
  values: Record<string, string> | null;
  types: SecretType[];
  categories: string[];
  categoryOf: (s: Secret) => CategorySummary | undefined;
  run: Run;
  onClose: () => void;
  onSaved: (saved: Secret) => void;
}) {
  const editing = props.secret;
  const [typeId, setTypeId] = useState<string>(editing?.type ?? (editing ? PLAIN : "api_key"));
  const [name, setName] = useState(editing?.name ?? "");
  const [category, setCategory] = useState(editing?.category ?? "");
  const [notes, setNotes] = useState(editing?.notes ?? "");
  const [icon, setIcon] = useState<string | null>(editing?.icon ?? null);
  const [color, setColor] = useState<string | null>(editing?.color ?? null);
  const [styling, setStyling] = useState(false);
  const [fields, setFields] = useState<Record<string, string>>(() => ({ ...(props.values ?? {}) }));
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  const type = props.types.find((t) => t.id === typeId);
  const formFields = useMemo(
    () => type?.fields ?? [
      { id: "username", label: "Username", kind: "Username" as const, secret: false, main: false, options: null },
      { id: "value", label: "Value", kind: "SecretText" as const, secret: true, main: true, options: null },
    ],
    [type],
  );

  const set = (id: string, value: string) => setFields((f) => ({ ...f, [id]: value }));
  const generate = async (id: string) => {
    const pw = await props.run(() => api.generatePassword(24, true));
    if (pw) {
      set(id, pw);
      setShown((s) => ({ ...s, [id]: true }));
    }
  };

  const mainField = formFields.find((f) => f.main);
  const initial = useMemo(() => JSON.stringify([props.values ?? {}, editing?.name ?? "", editing?.category ?? "", editing?.notes ?? ""]), [props.values, editing]);
  const nonEmpty = (f: Record<string, string>) => Object.fromEntries(Object.entries(f).filter(([, v]) => v !== ""));
  const dirty = editing
    ? (JSON.stringify([nonEmpty(fields), name, category, notes]) !== JSON.stringify([nonEmpty(JSON.parse(initial)[0]), ...JSON.parse(initial).slice(1)])
       || icon !== (editing.icon ?? null) || color !== (editing.color ?? null))
    : Object.values(fields).some((v) => v !== "") || name !== "" || category !== "" || notes !== "";
  const canSave = name.trim() !== "" && (!mainField || (fields[mainField.id] ?? "") !== "" || !!editing);

  const save = async () => {
    setBusy(true);
    const ids = new Set(formFields.map((f) => f.id));
    const saved = await props.run(() =>
      api.save({
        originalName: editing?.name ?? null,
        name: name.trim(),
        typeId: typeId || null,
        fields: Object.fromEntries(Object.entries(fields).filter(([k]) => ids.has(k))),
        category: category.trim() || null,
        notes: notes.trim() || null,
        icon,
        color,
      }),
    );
    setBusy(false);
    if (saved) props.onSaved(saved);
  };

  return (
    <Drawer
      title={editing ? `Edit ${editing.name}` : "New secret"}
      onClose={props.onClose}
      dirty={dirty && !busy}
      footer={
        <>
          <button className="button" onClick={props.onClose}>Cancel</button>
          <button className="button primary" onClick={save} disabled={!canSave || busy}>{editing ? "Save" : "Add secret"}</button>
        </>
      }
    >
      <form className="form" onSubmit={(e) => { e.preventDefault(); if (canSave) save(); }}>
        {!editing && (
          <div className="type-picker" role="radiogroup" aria-label="Type">
            {props.types.map((t) => {
              const Icon = iconFor(t.icon);
              return (
                <button type="button" key={t.id} role="radio" aria-checked={typeId === t.id}
                  className={`type-option${typeId === t.id ? " active" : ""}`} onClick={() => setTypeId(t.id)}>
                  <Icon size={18} /> {t.name}
                </button>
              );
            })}
            <button type="button" role="radio" aria-checked={typeId === PLAIN}
              className={`type-option${typeId === PLAIN ? " active" : ""}`} onClick={() => setTypeId(PLAIN)}>
              {(() => { const Icon = iconFor(null); return <Icon size={18} />; })()} Plain value
            </button>
          </div>
        )}

        <label className="form-row">
          <span>Name</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="github-token" spellCheck={false} />
          <small className="muted">What agents and commands use to refer to it.</small>
        </label>

        {formFields.map((f) => {
          const value = fields[f.id] ?? "";
          const listId = f.options ? `opts-${f.id}` : undefined;
          return (
            <label className="form-row" key={f.id}>
              <span>{f.label}{f.main && <em className="muted"> · main value</em>}</span>
              <div className="input-group">
                {f.kind === "SecretText" && (shown[f.id] || !f.secret) ? (
                  <textarea value={value} onChange={(e) => set(f.id, e.target.value)} rows={4} spellCheck={false} className="mono" />
                ) : (
                  <input
                    type={f.secret && !shown[f.id] ? "password" : f.kind === "Number" ? "number" : "text"}
                    value={value}
                    onChange={(e) => set(f.id, e.target.value)}
                    list={listId}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder={editing && f.secret && !value ? "unchanged" : f.kind === "Url" ? "https://" : ""}
                    className={f.secret ? "mono" : ""}
                  />
                )}
                {f.secret && (
                  <>
                    <button type="button" className="icon-button" onClick={() => setShown((s) => ({ ...s, [f.id]: !s[f.id] }))}
                      aria-label={shown[f.id] ? "Hide" : "Show"}>
                      {shown[f.id] ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    {f.kind === "Password" && (
                      <button type="button" className="icon-button" onClick={() => generate(f.id)} title="Generate a password" aria-label="Generate">
                        <Wand2 size={16} />
                      </button>
                    )}
                  </>
                )}
              </div>
              {listId && <datalist id={listId}>{f.options!.map((o) => <option key={o} value={o} />)}</datalist>}
            </label>
          );
        })}

        <div className="form-row">
          <span>Category</span>
          <CategoryPicker value={category} onChange={setCategory} categories={props.categories} />
        </div>

        <div className="form-row">
          <span>Icon and colour</span>
          <div className="style-preview">
            {/* As it will show: its own choice, else its category's, else its type's. */}
            <SecretIcon
              secret={{ ...(editing ?? ({} as Secret)), name, category: category || null, icon, color, type: typeId || null, linked: false }}
              type={type}
              category={category ? props.categoryOf({ category } as Secret) : undefined}
              size={36}
            />
            <span className="muted small-text">{icon || color ? "Its own" : "From its category or type"}</span>
            <button type="button" className="button small" onClick={() => setStyling(!styling)}>{styling ? "Done" : "Change"}</button>
          </div>
          {styling && (
            <div className="style-pickers">
              <IconPicker value={icon} allowDefault onChange={setIcon} />
              <ColorPicker value={color} onChange={setColor} />
            </div>
          )}
        </div>

        <label className="form-row">
          <span>Notes</span>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} maxLength={255} />
        </label>
        <button type="submit" hidden />
      </form>
    </Drawer>
  );
}
