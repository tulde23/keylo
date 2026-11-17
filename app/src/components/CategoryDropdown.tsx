import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown, Folder, Plus, Search } from "lucide-react";
import type { CategorySummary } from "../api";
import { IconTile } from "./ui";

type Row =
  | { kind: "category"; name: string; icon: string | null; color: string | null; count: number | null }
  | { kind: "create"; name: string }
  | { kind: "none" };

const same = (a: string, b: string) => a.localeCompare(b, undefined, { sensitivity: "base" }) === 0;

/**
 * Pick one category, or type a new one: a button with the category's icon, opening a list you can
 * filter by typing. "Create …" adds what was typed when nothing matches; the last row clears it.
 * Arrow keys, Enter and Esc work; Esc closes the list only.
 */
export default function CategoryDropdown({ value, onChange, categories, noneLabel = "None" }: {
  value: string;
  onChange: (category: string) => void;
  categories: CategorySummary[];
  /** What no category means here: "None", or e.g. "From subfolders" when importing. */
  noneLabel?: string;
}) {
  const [open, setOpen] = useState(false);
  // Open upward when there isn't room below (the field near the bottom of a panel).
  const [up, setUp] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);

  const chosen = categories.find((c) => same(c.name, value));

  const rows = useMemo<Row[]>(() => {
    const q = query.trim();
    const all: Row[] = categories
      .filter((c) => !q || c.name.toLowerCase().includes(q.toLowerCase()))
      .map((c) => ({ kind: "category" as const, name: c.name, icon: c.icon, color: c.color, count: c.count }));
    // One typed in this form but not saved yet is still listed (and chosen).
    if (value && !chosen && (!q || value.toLowerCase().includes(q.toLowerCase()))) {
      all.unshift({ kind: "category", name: value, icon: null, color: null, count: null });
    }
    if (q && !categories.some((c) => same(c.name, q)) && !(value && same(value, q))) all.unshift({ kind: "create", name: q });
    all.push({ kind: "none" });
    return all;
  }, [categories, query, value, chosen]);

  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => root.current && !root.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", down);
    return () => window.removeEventListener("mousedown", down);
  }, [open]);

  useEffect(() => {
    if (open) list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  // Typing moves the highlight to the first row (the "Create" row when there's one).
  useEffect(() => setActive(0), [query]);

  const show = () => {
    setQuery("");
    const i = rows.findIndex((r) => (r.kind === "category" && same(r.name, value)) || (r.kind === "none" && !value));
    setActive(Math.max(0, i));
    const box = root.current?.getBoundingClientRect();
    setUp(!!box && window.innerHeight - box.bottom < 380 && box.top > window.innerHeight - box.bottom);
    setOpen(true);
  };
  const choose = (r: Row) => {
    onChange(r.kind === "none" ? "" : r.name.trim());
    setOpen(false);
  };

  const key = (e: React.KeyboardEvent) => {
    const handled = () => { e.preventDefault(); e.stopPropagation(); };
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter"].includes(e.key)) { handled(); show(); }
      return;
    }
    switch (e.key) {
      case "ArrowDown": handled(); setActive((a) => Math.min(rows.length - 1, a + 1)); break;
      case "ArrowUp": handled(); setActive((a) => Math.max(0, a - 1)); break;
      case "Enter": handled(); if (rows[active]) choose(rows[active]); break;
      case "Escape": handled(); setOpen(false); break;
      case "Tab": setOpen(false); break;
    }
  };

  return (
    <div className="type-dropdown" ref={root} onKeyDown={key}>
      <button type="button" className="type-dropdown-button" aria-haspopup="listbox" aria-expanded={open}
        aria-label={`Category: ${value || noneLabel}`} onClick={() => (open ? setOpen(false) : show())}>
        {value ? <IconTile icon={chosen?.icon ?? null} color={chosen?.color ?? null} size={18} fallback={Folder} />
          : <span className="dropdown-none-icon"><Folder size={14} /></span>}
        <span className={value ? undefined : "muted"}>{value || noneLabel}</span>
        <ChevronDown size={16} className="muted" />
      </button>
      {open && (
        <div className={`type-dropdown-list${up ? " up" : ""}`}>
          <div className="dropdown-search">
            <Search size={14} className="muted" />
            <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} maxLength={64}
              placeholder="Find or create a category" aria-label="Find or create a category" spellCheck={false} />
          </div>
          <ul role="listbox" aria-label="Category" ref={list}>
            {rows.map((r, n) => {
              const selected = r.kind === "category" ? same(r.name, value) : r.kind === "none" && !value;
              return (
                <li key={r.kind === "none" ? "\u0000none" : `${r.kind}:${r.name}`} role="option" aria-selected={selected} data-index={n}
                  className={`type-dropdown-item${n === active ? " active" : ""}${r.kind === "none" ? " none-row" : ""}`}
                  onMouseEnter={() => setActive(n)} onMouseDown={(e) => { e.preventDefault(); choose(r); }}>
                  {r.kind === "category" && <IconTile icon={r.icon} color={r.color} size={18} fallback={Folder} />}
                  {r.kind === "create" && <span className="dropdown-none-icon accent"><Plus size={14} /></span>}
                  {r.kind === "none" && <span className="dropdown-none-icon" />}
                  <span>
                    {r.kind === "category" && r.name}
                    {r.kind === "create" && <>Create <strong>“{r.name}”</strong></>}
                    {r.kind === "none" && <span className="muted">{noneLabel}</span>}
                  </span>
                  {r.kind === "category" && r.count !== null && <small className="muted">{r.count}</small>}
                  {selected && <Check size={15} className="type-dropdown-check" />}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
