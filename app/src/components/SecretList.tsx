import { useMemo } from "react";
import { Pin, Plus } from "lucide-react";
import { timeAgo, type CategorySummary, type RecentUse, type Secret, type SecretType } from "../api";
import type { View } from "./Sidebar";
import { SecretIcon } from "./ui";

/** Every term must match the name, category, username, notes, type or a non-secret field (as keylo list). */
function matches(s: Secret, query: string): boolean {
  const has = (v: string | null | undefined, t: string) => !!v && v.toLowerCase().includes(t);
  return query.toLowerCase().split(/\s+/).filter(Boolean).every((term) => {
    if (term.startsWith("cat:")) return has(s.category, term.slice(4));
    if (term.startsWith("type:")) return has(s.type, term.slice(5));
    return has(s.name, term) || has(s.category, term) || has(s.username, term) || has(s.notes, term) ||
      has(s.type, term) || Object.values(s.fields).some((v) => has(v, term));
  });
}

export default function SecretList(props: {
  view: View;
  secrets: Secret[];
  recent: RecentUse[];
  typeOf: (s: Secret) => SecretType | undefined;
  categoryOf: (s: Secret) => CategorySummary | undefined;
  query: string;
  selected: string | null;
  onSelect: (name: string) => void;
  onNew: () => void;
}) {
  const { view, secrets, query } = props;
  const groups = useMemo((): [string | null, Secret[]][] => {
    if (query.trim()) return [[null, secrets.filter((s) => matches(s, query))]];
    if (view === "home") {
      const byName = new Map(secrets.map((s) => [s.name.toLowerCase(), s]));
      const pinned = secrets.filter((s) => s.pinned);
      const used = props.recent
        .map((u) => byName.get(u.name.toLowerCase()))
        .filter((s): s is Secret => !!s && !s.pinned);
      // Nothing pinned or used yet (a new install): everything, so Home is never a dead end.
      if (pinned.length === 0 && used.length === 0) return [["All secrets", secrets]];
      return [["Pinned", pinned], ["Recently used", used], ["Everything else", secrets.filter((s) => !s.pinned && !used.includes(s))]];
    }
    const inView = secrets.filter((s) =>
      view === "all" ? true
        : view.startsWith("cat:") ? s.category === view.slice(4)
        : view.startsWith("type:") ? s.type === view.slice(5) : false);
    return [[null, inView]];
  }, [secrets, props.recent, view, query]);

  const title = query.trim() ? "Search results"
    : view === "home" ? "Home"
    : view === "all" ? "All secrets"
    : view.startsWith("cat:") ? view.slice(4)
    : props.typeOf({ type: view.slice(5) } as Secret)?.name ?? "Secrets";

  const total = groups.reduce((n, [, list]) => n + list.length, 0);
  const lastUse = (name: string) => props.recent.find((u) => u.name.toLowerCase() === name.toLowerCase());

  return (
    <section className="list-pane" aria-label={title}>
      <div className="list-title">
        <h1>{title}</h1>
        <span className="muted">{total === 1 ? "1 item" : `${total} items`}</span>
      </div>
      <div className="list-scroll">
        {total === 0 ? (
          <div className="empty">
            {secrets.length === 0 ? (
              <>
                <p><strong>No secrets yet</strong></p>
                <p className="muted">Add your first API key, password or token.</p>
                <button className="button primary" onClick={props.onNew}><Plus size={16} /> New secret</button>
              </>
            ) : view === "home" && !query ? (
              <>
                <p><strong>Nothing pinned or used yet</strong></p>
                <p className="muted">Pin the secrets you use most, or find them under All secrets.</p>
              </>
            ) : (
              <p className="muted">Nothing matches.</p>
            )}
          </div>
        ) : (
          groups.map(([heading, list]) =>
            list.length === 0 ? null : (
              <div key={heading ?? "all"}>
                {heading && <h2 className="group-heading">{heading}</h2>}
                <ul className="secret-rows" role="listbox">
                  {list.map((s) => {
                    const t = props.typeOf(s);
                    const use = view === "home" && !s.pinned ? lastUse(s.name) : undefined;
                    return (
                      <li key={s.name}>
                        <button
                          role="option"
                          aria-selected={props.selected === s.name}
                          className={`secret-row${props.selected === s.name ? " selected" : ""}`}
                          onClick={() => props.onSelect(s.name)}
                        >
                          <SecretIcon secret={s} type={t} category={props.categoryOf(s)} />
                          <span className="row-text">
                            <span className="row-name">{s.name}</span>
                            <span className="row-sub">
                              {use ? `${use.who === "You" ? "You" : use.who} · ${use.action} ${timeAgo(use.time)}`
                                : [s.username, s.category, t?.name].filter(Boolean).join(" · ") || "Secret"}
                            </span>
                          </span>
                          {s.pinned && <Pin size={14} className="row-pin" />}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))
        )}
      </div>
    </section>
  );
}
