import { useState } from "react";
import { Check, Folder, Plus, Trash2 } from "lucide-react";
import { api, type CategorySummary } from "../api";
import type { Run } from "../App";
import { ColorPicker, Drawer, IconPicker, iconFor, useToast } from "./ui";

/**
 * Create, rename (renaming onto another merges them), style and delete categories. Categories live
 * on the secrets; empty ones and styles are kept in categories.json.
 */
export default function CategoryManager({ categories, run, onChanged, onClose }: {
  categories: CategorySummary[];
  run: Run;
  onChanged: (categories: CategorySummary[]) => void;
  onClose: () => void;
}) {
  const toast = useToast();
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState("");

  const apply = async (call: () => Promise<CategorySummary[]>, done?: string) => {
    const updated = await run(call);
    if (updated) {
      onChanged(updated);
      if (done) toast(done);
    }
    return !!updated;
  };

  const create = async () => {
    const name = adding.trim();
    if (!name) return;
    if (await apply(() => api.createCategory(name, null, null), `Added '${name}'.`)) setAdding("");
  };

  return (
    <Drawer title="Categories" onClose={onClose} footer={<button className="button primary" onClick={onClose}>Done</button>}>
      <form className="add-category" onSubmit={(e) => { e.preventDefault(); create(); }}>
        <input value={adding} onChange={(e) => setAdding(e.target.value)} placeholder="New category" aria-label="New category" maxLength={64} />
        <button className="button" type="submit" disabled={!adding.trim()}><Plus size={15} /> Add</button>
      </form>
      {categories.length === 0 && <p className="muted">No categories yet.</p>}
      <ul className="category-list">
        {categories.map((c) => (
          <CategoryRow
            key={c.name}
            category={c}
            others={categories.filter((o) => o.name !== c.name).map((o) => o.name)}
            expanded={open === c.name}
            onToggle={() => setOpen(open === c.name ? null : c.name)}
            apply={apply}
          />
        ))}
      </ul>
    </Drawer>
  );
}

function CategoryRow({ category: c, others, expanded, onToggle, apply }: {
  category: CategorySummary;
  others: string[];
  expanded: boolean;
  onToggle: () => void;
  apply: (call: () => Promise<CategorySummary[]>, done?: string) => Promise<boolean>;
}) {
  const [name, setName] = useState(c.name);
  const [deleting, setDeleting] = useState(false);
  const [moveTo, setMoveTo] = useState("");
  const Icon = c.icon ? iconFor(c.icon) : Folder;
  const merging = others.find((o) => o.toLowerCase() === name.trim().toLowerCase());

  const rename = () => {
    const to = name.trim();
    if (!to || to === c.name) return setName(c.name);
    apply(() => api.renameCategory(c.name, to),
      merging ? `Merged '${c.name}' into '${merging}'.` : `Renamed '${c.name}' to '${to}'.`);
  };

  const remove = (deleteSecrets: boolean) =>
    apply(() => api.deleteCategory(c.name, deleteSecrets ? null : moveTo || null, deleteSecrets),
      deleteSecrets ? `Deleted '${c.name}' and its secrets.` : `Deleted '${c.name}'.`);

  return (
    <li className={`category-row${expanded ? " expanded" : ""}`}>
      <div className="category-main">
        <button className="secret-icon category-style" style={{ width: 32, height: 32, ...(c.color ? { background: c.color, color: "#fff" } : {}) }}
          onClick={onToggle} title="Icon and colour" aria-label={`Icon and colour of ${c.name}`} aria-expanded={expanded}>
          <Icon size={16} />
        </button>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onBlur={rename}
          onKeyDown={(e) => {
            if (e.key === "Enter") e.currentTarget.blur();
            if (e.key === "Escape") { e.stopPropagation(); setName(c.name); }
          }}
          aria-label={`Name of ${c.name}`}
          maxLength={64}
        />
        <span className="muted category-count">{c.count === 1 ? "1 secret" : `${c.count} secrets`}</span>
        <button className="icon-button danger" onClick={() => setDeleting(!deleting)} aria-label={`Delete ${c.name}`} title="Delete"><Trash2 size={16} /></button>
      </div>
      {merging && name.trim() !== c.name && (
        <p className="muted small-text">'{merging}' exists: renaming merges the two.</p>
      )}
      {expanded && (
        <div className="category-style-pickers">
          <IconPicker value={c.icon} allowDefault onChange={(icon) => apply(() => api.setCategoryStyle(c.name, icon, c.color))} />
          <ColorPicker value={c.color} onChange={(color) => apply(() => api.setCategoryStyle(c.name, c.icon, color))} />
        </div>
      )}
      {deleting && (
        <div className="category-delete">
          {c.count === 0 ? (
            <button className="button danger-fill small" onClick={() => remove(false)}><Check size={14} /> Delete '{c.name}'</button>
          ) : (
            <>
              <label className="form-row">
                <span>Move its {c.count === 1 ? "secret" : `${c.count} secrets`} to</span>
                <select value={moveTo} onChange={(e) => setMoveTo(e.target.value)}>
                  <option value="">No category</option>
                  {others.map((o) => <option key={o} value={o}>{o}</option>)}
                </select>
              </label>
              <div className="category-delete-actions">
                <button className="button small" onClick={() => remove(false)}>Delete the category, keep the secrets</button>
                <button className="button danger-fill small" onClick={() => remove(true)}>Delete it and its secrets</button>
              </div>
            </>
          )}
        </div>
      )}
    </li>
  );
}
