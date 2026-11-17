import { useEffect, useMemo, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import type { SecretType } from "../api";
import { IconTile } from "./ui";

/** Built-in types listed first; the other built-ins follow under "More". */
const COMMON = ["login", "api_key", "password", "database", "ssh_key", "note"];
const PLAIN = "";

interface Item {
  id: string;
  name: string;
  icon: string | null;
  color: string | null;
}

/**
 * The secret-type picker: a button with the chosen type's icon, opening a grouped list (Common,
 * More, your own types, Plain value) with an icon on each. Arrow keys, Home/End, Enter and Esc work;
 * Esc closes the list only.
 */
export default function TypeDropdown({ types, value, onChange }: {
  types: SecretType[];
  value: string;
  onChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  // Open upward when there isn't room below (the field near the bottom of a panel).
  const [up, setUp] = useState(false);
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const list = useRef<HTMLUListElement>(null);

  const groups = useMemo(() => {
    const item = (t: SecretType): Item => ({ id: t.id, name: t.name, icon: t.icon, color: t.color });
    const builtIn = types.filter((t) => t.builtIn);
    const result: { label: string; items: Item[] }[] = [
      { label: "Common", items: COMMON.map((id) => builtIn.find((t) => t.id === id)).filter((t): t is SecretType => !!t).map(item) },
      { label: "More", items: builtIn.filter((t) => !COMMON.includes(t.id)).map(item) },
    ];
    const custom = types.filter((t) => !t.builtIn);
    if (custom.length) result.push({ label: "Your types", items: custom.map(item) });
    result.push({ label: "", items: [{ id: PLAIN, name: "Plain value", icon: null, color: null }] });
    return result.filter((g) => g.items.length > 0);
  }, [types]);
  const flat = groups.flatMap((g) => g.items);
  const current = flat.find((i) => i.id === value) ?? flat[flat.length - 1];

  // Click outside closes it.
  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => root.current && !root.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", down);
    return () => window.removeEventListener("mousedown", down);
  }, [open]);

  // Keep the highlighted item in view.
  useEffect(() => {
    if (open) list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  const show = () => {
    setActive(Math.max(0, flat.findIndex((i) => i.id === value)));
    const box = root.current?.getBoundingClientRect();
    setUp(!!box && window.innerHeight - box.bottom < 380 && box.top > window.innerHeight - box.bottom);
    setOpen(true);
  };
  const choose = (i: Item) => {
    onChange(i.id);
    setOpen(false);
  };

  const key = (e: React.KeyboardEvent) => {
    const handled = () => { e.preventDefault(); e.stopPropagation(); };
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) { handled(); show(); }
      return;
    }
    switch (e.key) {
      case "ArrowDown": handled(); setActive((a) => Math.min(flat.length - 1, a + 1)); break;
      case "ArrowUp": handled(); setActive((a) => Math.max(0, a - 1)); break;
      case "Home": handled(); setActive(0); break;
      case "End": handled(); setActive(flat.length - 1); break;
      case "Enter": case " ": handled(); choose(flat[active]); break;
      case "Escape": handled(); setOpen(false); break;
      case "Tab": setOpen(false); break;
    }
  };

  let index = -1;
  return (
    <div className="type-dropdown" ref={root} onKeyDown={key}>
      <button type="button" className="type-dropdown-button" aria-haspopup="listbox" aria-expanded={open}
        aria-label={`Type: ${current.name}`} onClick={() => (open ? setOpen(false) : show())}>
        <IconTile icon={current.icon} color={current.color} size={18} />
        <span>{current.name}</span>
        <ChevronDown size={16} className="muted" />
      </button>
      {open && (
        <ul className={`type-dropdown-list${up ? " up" : ""}`} role="listbox" aria-label="Type" ref={list}>
          {groups.map((g) => (
            <li key={g.label || "plain"} role="presentation">
              {g.label && <div className="type-dropdown-group">{g.label}</div>}
              <ul role="group" aria-label={g.label || "Plain"}>
                {g.items.map((i) => {
                  index += 1;
                  const n = index;
                  return (
                    <li key={i.id || "plain"} role="option" aria-selected={i.id === value} data-index={n}
                      className={`type-dropdown-item${n === active ? " active" : ""}`}
                      onMouseEnter={() => setActive(n)} onMouseDown={(e) => { e.preventDefault(); choose(i); }}>
                      <IconTile icon={i.icon} color={i.color} size={18} />
                      <span>{i.name}</span>
                      {i.id === value && <Check size={15} className="type-dropdown-check" />}
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
