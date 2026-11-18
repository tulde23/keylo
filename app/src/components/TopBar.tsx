import { useEffect, useRef } from "react";
import { Activity, FileDown, FolderDown, Link2, Lock, Plus, Search, Settings, X } from "lucide-react";
import { IS_MAC, shortcut } from "./ui";

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
  /** Pick files (or, with `folder`, a folder) and import them. */
  onImport: (folder: boolean) => void;
  onLink: () => void;
  onSettings: () => void;
  onActivity: () => void;
  activityActive: boolean;
  onLock: () => void;
  settingsActive: boolean;
  lockTitle: string;
}) {
  const search = useRef<HTMLInputElement>(null);
  const { onNew, onLock } = props;

  // Ctrl+K (⌘K on a Mac; or Ctrl+F, or "/" outside a text box) searches; Ctrl+N adds a secret; Ctrl+L locks.
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement;
      // ⌘ on a Mac (where Ctrl+K, Ctrl+F and Ctrl+N are text-editing keys), Ctrl elsewhere.
      const ctrl = IS_MAC ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey;
      const k = e.key.toLowerCase(); // Caps Lock or Shift still count
      if ((ctrl && (k === "k" || k === "f")) || (e.key === "/" && !typing)) {
        e.preventDefault();
        search.current?.focus();
        search.current?.select();
      } else if (ctrl && k === "n") {
        e.preventDefault();
        onNew();
      } else if (ctrl && k === "l") {
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
          <kbd>{shortcut("K")}</kbd>
        )}
      </div>

      <div className="topbar-tiles">
        <button className="tile accent" onClick={props.onNew} title={`New secret (${shortcut("N")})`} aria-label="New secret">
          <Plus size={18} />
        </button>
        <button className="tile quiet" onClick={() => props.onImport(false)} title="Import files as secrets" aria-label="Import files">
          <FileDown size={18} />
        </button>
        <button className="tile quiet" onClick={() => props.onImport(true)} title="Import a folder; subfolders become categories" aria-label="Import folder">
          <FolderDown size={18} />
        </button>
        <button className="tile quiet" onClick={props.onLink} title="Link from 1Password or AWS Secrets Manager" aria-label="Link from a vault">
          <Link2 size={18} />
        </button>
        <span className="toolbar-gap" />
        <button className={`tile quiet${props.activityActive ? " active" : ""}`} onClick={props.onActivity}
          title="Activity: every use of a secret by an agent or tool" aria-label="Activity">
          <Activity size={18} />
        </button>
        <button className={`tile quiet${props.settingsActive ? " active" : ""}`} onClick={props.onSettings} title="Settings" aria-label="Settings">
          <Settings size={18} />
        </button>
        <button className="tile quiet" onClick={props.onLock} title={`${props.lockTitle} (${shortcut("L")})`} aria-label="Lock">
          <Lock size={18} />
        </button>
      </div>
    </header>
  );
}
