import { useMemo, useState } from "react";
import { Eye, EyeOff, Wand2 } from "lucide-react";
import { api, type CategorySummary, type Field, type Secret, type SecretType } from "../api";
import type { Run } from "../App";
import CategoryDropdown from "./CategoryDropdown";
import TypeDropdown from "./TypeDropdown";
import { ColorPicker, Drawer, IconPicker, SecretIcon } from "./ui";

const PLAIN = "";



const PLAIN_FIELDS: Field[] = [
  { id: "username", label: "Username", kind: "Username", secret: false, main: false, options: null },
  { id: "value", label: "Value", kind: "SecretText", secret: true, main: true, options: null },
];

/** Adds or edits a secret. `values` are the revealed fields of the secret being edited. */
export default function SecretEditor(props: {
  secret: Secret | null;
  values: Record<string, string> | null;
  types: SecretType[];
  categories: CategorySummary[];
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

  const linked = !!editing?.linked;
  const type = props.types.find((t) => t.id === typeId);
  const fieldsOf = (id: string): Field[] => props.types.find((t) => t.id === id)?.fields ?? PLAIN_FIELDS;
  const formFields = useMemo(
    // A link's values live in its vault: only its name and details are edited here.
    () => linked ? [] : type?.fields ?? PLAIN_FIELDS,
    [type, linked],
  );

  // Changing an existing secret's type: values move to the new type's fields with the same id, or
  // the same role (main value, username, website). What has no place there is listed before saving.
  const originalType = editing ? editing.type ?? PLAIN : null;
  const [dropped, setDropped] = useState<string[]>([]);
  const changeType = (id: string) => {
    if (!editing) return setTypeId(id);
    const from = fieldsOf(originalType ?? PLAIN);
    const to = fieldsOf(id);
    const original = props.values ?? {};
    const next: Record<string, string> = {};
    const used = new Set<string>();
    const move = (dest: Field | undefined, src: Field | undefined) => {
      if (!dest || !src || next[dest.id] || used.has(src.id) || !original[src.id]) return;
      next[dest.id] = original[src.id];
      used.add(src.id);
    };
    for (const d of to) move(d, from.find((f) => f.id === d.id));
    move(to.find((f) => f.main), from.find((f) => f.main));
    move(to.find((f) => f.kind === "Username"), from.find((f) => f.kind === "Username"));
    move(to.find((f) => f.kind === "Url"), from.find((f) => f.kind === "Url"));
    // Edits made in this panel to fields the new type also has stay.
    for (const d of to) if (fields[d.id] && fields[d.id] !== original[d.id]) next[d.id] = fields[d.id];
    setFields(next);
    setDropped(id === originalType ? [] : from.filter((f) => original[f.id] && !used.has(f.id)).map((f) => f.label));
    setTypeId(id);
  };
  const typeChanged = !!editing && typeId !== originalType;

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
       || icon !== (editing.icon ?? null) || color !== (editing.color ?? null) || typeChanged)
    : Object.values(fields).some((v) => v !== "") || name !== "" || category !== "" || notes !== "";
  // A new secret, or one changing type, needs its main value; otherwise an empty secret field keeps the stored one.
  const canSave = name.trim() !== "" && (!mainField || (fields[mainField.id] ?? "") !== "" || (!!editing && !typeChanged));

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
        {!linked && (
          <div className="form-row">
            <span>Type</span>
            <TypeDropdown types={props.types} value={typeId} onChange={changeType} />
          </div>
        )}
        {typeChanged && dropped.length > 0 && (
          <p className="warning small-text">
            {dropped.join(", ")} {dropped.length === 1 ? "has" : "have"} no place in {type?.name ?? "a plain value"} and won't be kept when you save.
          </p>
        )}

        {editing?.link && (
          <p className="notice">
            Linked to <strong>{editing.link.title}</strong> in {editing.link.providerName}. Its values stay there; only the name and
            details change here.
          </p>
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
                    placeholder={editing && f.secret && !value ? "unchanged" : f.kind === "Url" ? "https://" : f.kind === "Totp" ? "Setup key or otpauth:// link" : ""}
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
          <CategoryDropdown value={category} onChange={setCategory} categories={props.categories} />
        </div>

        <div className="form-row">
          <span>Icon and colour</span>
          <div className="style-preview">
            {/* As it will show: its own choice, else its category's, else its type's. */}
            <SecretIcon
              secret={{ ...(editing ?? ({} as Secret)), name, category: category || null, icon, color, type: typeId || null }}
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
