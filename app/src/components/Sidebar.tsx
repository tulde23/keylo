import { Activity, Folder, Home, Layers, Pencil } from "lucide-react";
import type { AppInfo, CategorySummary, Secret, SecretType } from "../api";
import { IconView } from "./ui";

/** "home", "all", "cat:NAME", "type:ID", "activity" or "settings". */
export type View = string;

export default function Sidebar(props: {
  view: View;
  onView: (v: View) => void;
  categories: CategorySummary[];
  types: SecretType[];
  secrets: Secret[];
  onManageCategories: () => void;
  info: AppInfo;
}) {
  const { view, onView } = props;
  const usedTypes = props.types
    .map((t) => [t, props.secrets.filter((s) => s.type === t.id).length] as const)
    .filter(([, n]) => n > 0);

  const item = (key: View, label: string, icon: typeof Home | string | null, count?: number, color?: string | null) => (
    <button key={key} className={`nav-item${view === key ? " active" : ""}`} onClick={() => onView(key)}
      aria-current={view === key ? "page" : undefined}>
      {typeof icon === "string" || icon === null
        ? <IconView icon={icon} size={16} fallback={Folder} style={color ? { color } : undefined} />
        : (() => { const Icon = icon; return <Icon size={16} style={color ? { color } : undefined} />; })()}
      <span className="nav-label">{label}</span>
      {count !== undefined && <span className="nav-count">{count}</span>}
    </button>
  );

  return (
    <nav className="sidebar" aria-label="Secrets">
      <div className="nav-section">
        {item("home", "Home", Home)}
        {item("all", "All secrets", Layers, props.secrets.length)}
      </div>

      <div className="nav-section">
        <div className="nav-heading">
          <h3>Categories</h3>
          <button className="nav-manage" onClick={props.onManageCategories} title="Create, rename, merge, delete, and set icons">
            <Pencil size={12} /> Manage
          </button>
        </div>
        {props.categories.map((c) => item(`cat:${c.name}`, c.name, c.icon, c.count, c.color))}
      </div>

      {usedTypes.length > 0 && (
        <div className="nav-section">
          <h3>Types</h3>
          {usedTypes.map(([t, n]) => item(`type:${t.id}`, t.name, t.icon, n))}
        </div>
      )}

      <div className="nav-bottom">
        {item("activity", "Activity", Activity)}
        <div className="build" title={`${props.info.storeName} · ${props.info.dataDir}`}>Keylo {props.info.version}</div>
      </div>
    </nav>
  );
}
