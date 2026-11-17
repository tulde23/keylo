import { useState } from "react";
import { Check, Plus, X } from "lucide-react";

/**
 * Pick one category: every existing one is a chip (click to choose, click again for none), and
 * "New category" types a new one. A text box with suggestions only offered names matching what was
 * already typed, so a secret's category couldn't be switched without clearing it first.
 */
export default function CategoryPicker({ value, onChange, categories }: {
  value: string;
  onChange: (category: string) => void;
  categories: string[];
}) {
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState("");
  const same = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" }) === 0;

  // A category typed in this form (not saved anywhere yet) still shows as a chip.
  const all = value && !categories.some((c) => same(c, value)) ? [...categories, value] : categories;

  const commit = () => {
    const name = draft.trim();
    if (name) onChange(all.find((c) => same(c, name)) ?? name);
    setDraft("");
    setAdding(false);
  };

  return (
    <div className="chip-picker" role="radiogroup" aria-label="Category">
      {all.map((c) => {
        const selected = same(c, value);
        return (
          <button type="button" key={c} role="radio" aria-checked={selected}
            className={`pick-chip${selected ? " active" : ""}`} onClick={() => onChange(selected ? "" : c)}>
            {selected && <Check size={14} />} {c}
          </button>
        );
      })}
      {adding ? (
        <span className="pick-chip-input">
          <input
            autoFocus
            value={draft}
            maxLength={64}
            placeholder="Category name"
            aria-label="New category name"
            onChange={(e) => setDraft(e.target.value)}
            onBlur={commit}
            onKeyDown={(e) => {
              // Enter adds it; Esc cancels (without closing the panel).
              if (e.key === "Enter") { e.preventDefault(); commit(); }
              if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); setDraft(""); setAdding(false); }
            }}
          />
          <button type="button" className="icon-button small" onMouseDown={(e) => e.preventDefault()}
            onClick={() => { setDraft(""); setAdding(false); }} aria-label="Cancel"><X size={14} /></button>
        </span>
      ) : (
        <button type="button" className="pick-chip add" onClick={() => setAdding(true)}>
          <Plus size={14} /> New category
        </button>
      )}
    </div>
  );
}
