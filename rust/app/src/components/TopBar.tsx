import { useEffect, useRef } from "react";
import { FileDown, Lock, Plus, Search, Settings, X } from "lucide-react";

export const TAGLINE = "Agents use them. Never see them.";

/**
 * The bar across the top, ported from the C# app: the brand over the sidebar, search over the list,
 * action tiles over the detail area. Its columns follow the panes below (CSS subgrid), so the search
 * box stays above the list. The window keeps the system's own title bar and buttons.
 */
export default function TopBar(props: {
  query: string;
  onQuery: (q: string) => void;
  onNew: () => void;
  onImport: () => void;
  onSettings: () => void;
  onLock: () => void;
  settingsActive: boolean;
  lockTitle: string;
}) {
  const search = useRef<HTMLInputElement>(null);
  const { onNew, onLock } = props;

  // Ctrl+K (or Ctrl+F, or "/" outside a text box) searches; Ctrl+N adds a secret; Ctrl+L locks.
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      const ctrl = e.ctrlKey || e.metaKey;
      if ((ctrl && (e.key === "k" || e.key === "f")) || (e.key === "/" && !typing)) {
        e.preventDefault();
        search.current?.focus();
        search.current?.select();
      } else if (ctrl && e.key === "n") {
        e.preventDefault();
        onNew();
      } else if (ctrl && e.key === "l") {
        e.preventDefault();
        onLock();
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onNew, onLock]);

  return (
    <header className="topbar">
      <div className="topbar-brand">
        <img src="/keylo.svg" alt="" width={26} height={26} />
        <div>
          <div className="brand-name">Keylo</div>
          <div className="brand-tagline">{TAGLINE}</div>
        </div>
      </div>

      <div className="topbar-search">
        <Search size={16} />
        <input
          ref={search}
          value={props.query}
          onChange={(e) => props.onQuery(e.target.value)}
          onKeyDown={(e) => e.key === "Escape" && props.onQuery("")}
          placeholder="Search all secrets…"
          aria-label="Search all secrets"
          spellCheck={false}
        />
        {props.query ? (
          <button className="icon-button small" onClick={() => props.onQuery("")} aria-label="Clear search"><X size={14} /></button>
        ) : (
          <kbd>Ctrl+K</kbd>
        )}
      </div>

      <div className="topbar-tiles">
        <button className="tile accent" onClick={props.onNew} title="New secret (Ctrl+N)" aria-label="New secret">
          <Plus size={18} />
        </button>
        <button className="tile quiet" onClick={props.onImport} title="Import files as secrets" aria-label="Import">
          <FileDown size={18} />
        </button>
        <span className="toolbar-gap" />
        <button className={`tile quiet${props.settingsActive ? " active" : ""}`} onClick={props.onSettings} title="Settings" aria-label="Settings">
          <Settings size={18} />
        </button>
        <button className="tile quiet" onClick={props.onLock} title={`${props.lockTitle} (Ctrl+L)`} aria-label="Lock">
          <Lock size={18} />
        </button>
      </div>
    </header>
  );
}
