import { Activity, Folder, Home, Layers } from "lucide-react";
import type { Secret, SecretType } from "../api";
import { iconFor } from "./ui";

/** "home", "all", "cat:NAME", "type:ID", "activity" or "settings". */
export type View = string;

export default function Sidebar(props: {
  view: View;
  onView: (v: View) => void;
  categories: [string, number][];
  types: SecretType[];
  secrets: Secret[];
}) {
  const { view, onView } = props;
  const usedTypes = props.types
    .map((t) => [t, props.secrets.filter((s) => s.type === t.id).length] as const)
    .filter(([, n]) => n > 0);

  const item = (key: View, label: string, Icon: typeof Home, count?: number) => (
    <button key={key} className={`nav-item${view === key ? " active" : ""}`} onClick={() => onView(key)}
      aria-current={view === key ? "page" : undefined}>
      <Icon size={16} />
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

      {props.categories.length > 0 && (
        <div className="nav-section">
          <h3>Categories</h3>
          {props.categories.map(([c, n]) => item(`cat:${c}`, c, Folder, n))}
        </div>
      )}

      {usedTypes.length > 0 && (
        <div className="nav-section">
          <h3>Types</h3>
          {usedTypes.map(([t, n]) => item(`type:${t.id}`, t.name, iconFor(t.icon), n))}
        </div>
      )}

      <div className="nav-bottom">
        {item("activity", "Activity", Activity)}
      </div>
    </nav>
  );
}
