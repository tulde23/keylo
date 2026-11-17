import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { api, LOCKED, message, type AppInfo, type CategorySummary, type RecentUse, type Secret, type SecretType, type Status } from "./api";
import CategoryManager from "./components/CategoryManager";
import ImportPanel from "./components/ImportPanel";
import LinkPanel from "./components/LinkPanel";
import LockScreen from "./components/LockScreen";
import Sidebar, { type View } from "./components/Sidebar";
import SecretList from "./components/SecretList";
import SecretDetail from "./components/SecretDetail";
import SecretEditor from "./components/SecretEditor";
import SettingsView from "./components/SettingsView";
import ActivityView from "./components/ActivityView";
import TopBar from "./components/TopBar";
import { ToastProvider, useToast } from "./components/ui";

export default function App() {
  return (
    <ToastProvider>
      <Shell />
    </ToastProvider>
  );
}

type Editing = { secret: Secret | null; values: Record<string, string> | null } | null;

function Shell() {
  const toast = useToast();
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [types, setTypes] = useState<SecretType[]>([]);
  const [recent, setRecent] = useState<RecentUse[]>([]);
  const [view, setView] = useState<View>("home");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [editing, setEditing] = useState<Editing>(null);
  const [categories, setCategories] = useState<CategorySummary[]>([]);
  const [managingCategories, setManagingCategories] = useState(false);
  const [importing, setImporting] = useState<string[] | null>(null);
  const [linking, setLinking] = useState(false);
  const [dropping, setDropping] = useState(false);

  /** Runs a backend call; a "locked" error shows the lock screen, others a toast. */
  const run = useCallback(async <T,>(call: () => Promise<T>): Promise<T | undefined> => {
    try {
      return await call();
    } catch (e) {
      const text = message(e);
      if (text === LOCKED) setStatus((s) => (s ? { ...s, unlocked: false } : s));
      else toast(text, true);
      return undefined;
    }
  }, [toast]);

  const refresh = useCallback(async () => {
    const [list, uses, cats] = await Promise.all([api.secrets(), api.recent(), api.categories()]);
    setSecrets(list);
    setRecent(uses);
    setCategories(cats);
  }, []);

  useEffect(() => {
    api.appInfo().then(setInfo);
    api.status().then(setStatus);
    api.types().then(setTypes).catch(() => {});
  }, []);

  // Reload on unlock, and when Settings opens (it counts secrets per type; the CLI may have added some).
  useEffect(() => {
    if (status?.unlocked) run(refresh);
  }, [status?.unlocked, refresh, run]);
  useEffect(() => {
    if (view === "settings" && status?.unlocked) run(refresh);
  }, [view, status?.unlocked, refresh, run]);

  // The screen locked: Keylo locked with it.
  useEffect(() => {
    const stop = listen("keylo://locked", () => {
      setSecrets([]);
      setSelected(null);
      setEditing(null);
      api.status().then(setStatus);
    });
    return () => { stop.then((f) => f()); };
  }, []);

  // Files dropped on the window, or given with `keylow --import`, open Import with them (once
  // unlocked; an open panel adds them).
  const unlocked = !!status?.unlocked;
  const addImports = useCallback((paths: string[]) => {
    if (paths.length) setImporting((current) => [...(current ?? []), ...paths.filter((x) => !current?.includes(x))]);
  }, []);
  useEffect(() => {
    if (!unlocked) return;
    api.takeStartupImport().then(addImports).catch(() => {});
    const stopArgs = listen<string[]>("keylo://import", (e) => addImports(e.payload));
    const stop = getCurrentWebview().onDragDropEvent((e) => {
      const p = e.payload;
      if (p.type === "enter") setDropping(true);
      else if (p.type === "leave") setDropping(false);
      else if (p.type === "drop") {
        setDropping(false);
        addImports(p.paths);
      }
    });
    return () => { stop.then((f) => f()); stopArgs.then((f) => f()); };
  }, [unlocked, addImports]);

  // Activity keeps the session alive; the session ending (or a lock from the CLI) shows the lock screen.
  const lastTouch = useRef(0);
  useEffect(() => {
    const onActivity = () => {
      if (Date.now() - lastTouch.current > 30_000) {
        lastTouch.current = Date.now();
        api.touch().catch(() => {});
      }
    };
    window.addEventListener("keydown", onActivity);
    window.addEventListener("pointerdown", onActivity);
    const poll = setInterval(() => api.status().then(setStatus).catch(() => {}), 20_000);
    return () => {
      window.removeEventListener("keydown", onActivity);
      window.removeEventListener("pointerdown", onActivity);
      clearInterval(poll);
    };
  }, []);

  const typeOf = useMemo(() => {
    const map = new Map(types.map((t) => [t.id, t]));
    return (s: Secret) => (s.type ? map.get(s.type) : undefined);
  }, [types]);

  const categoryOf = useMemo(() => {
    const map = new Map(categories.map((c) => [c.name.toLowerCase(), c]));
    return (s: Secret) => (s.category ? map.get(s.category.toLowerCase()) : undefined);
  }, [categories]);
  const categoryNames = categories.map((c) => c.name);

  const current = secrets.find((s) => s.name === selected) ?? null;

  if (!info || !status) return <div className="splash" />;
  if (!status.unlocked) {
    return (
      <LockScreen
        info={info}
        onUnlock={async () => {
          await api.unlock();
          setStatus(await api.status());
        }}
      />
    );
  }

  const lock = async () => {
    await api.lock();
    setSecrets([]);
    setSelected(null);
    setStatus(await api.status());
  };

  const isSecretsView = view === "home" || view === "all" || view.startsWith("cat:") || view.startsWith("type:");
  const newSecret = () => setEditing({ secret: null, values: null });
  const lockTitle = status.mode !== "never" && status.sessionExpires
    ? `Unlocked until ${new Date(status.sessionExpires).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "Lock";

  return (
    <div className="shell">
      <TopBar
        query={query}
        onQuery={(q) => {
          setQuery(q);
          // Searching covers every secret, wherever you are.
          if (q && !isSecretsView) setView("all");
        }}
        onNew={newSecret}
        onImport={() => setImporting([])}
        onLink={() => setLinking(true)}
        onSettings={() => setView(view === "settings" ? "home" : "settings")}
        onLock={lock}
        settingsActive={view === "settings"}
        lockTitle={lockTitle}
      />
      <Sidebar
        view={view}
        onView={(v) => { setView(v); setQuery(""); }}
        categories={categories}
        types={types}
        secrets={secrets}
        onManageCategories={() => setManagingCategories(true)}
        info={info}
      />
      {isSecretsView && (
        <>
          <SecretList
            view={view}
            secrets={secrets}
            recent={recent}
            typeOf={typeOf}
            categoryOf={categoryOf}
            query={query}
            selected={selected}
            onSelect={setSelected}
            onNew={newSecret}
          />
          <SecretDetail
            key={current?.name ?? "none"}
            secret={current}
            type={current ? typeOf(current) : undefined}
            category={current ? categoryOf(current) : undefined}
            info={info}
            run={run}
            onEdit={(values) => current && setEditing({ secret: current, values })}
            onChanged={async (name) => {
              await run(refresh);
              if (name !== undefined) setSelected(name);
            }}
          />
        </>
      )}
      {view === "activity" && <ActivityView run={run} />}
      {view === "settings" && (
        <SettingsView
          info={info}
          secrets={secrets}
          types={types}
          onTypes={setTypes}
          categories={categoryNames}
          run={run}
          onSettingsSaved={async () => setStatus(await api.status())}
          onDataChanged={() => { run(refresh); api.types().then(setTypes).catch(() => {}); }}
        />
      )}
      {editing && (
        <SecretEditor
          secret={editing.secret}
          values={editing.values}
          types={types}
          categories={categoryNames}
          categoryOf={categoryOf}
          run={run}
          onClose={() => setEditing(null)}
          onSaved={async (saved) => {
            setEditing(null);
            await run(refresh);
            setSelected(saved.name);
            toast(editing.secret ? `Saved '${saved.name}'.` : `Added '${saved.name}'.`);
          }}
        />
      )}
      {importing && (
        <ImportPanel
          initialPaths={importing}
          types={types}
          categories={categoryNames}
          run={run}
          onClose={() => setImporting(null)}
          onImported={() => run(refresh)}
        />
      )}
      {linking && (
        <LinkPanel
          categories={categoryNames}
          run={run}
          onClose={() => setLinking(false)}
          onLinked={async (name) => {
            await run(refresh);
            if (isSecretsView) setSelected(name);
            else { setView("all"); setSelected(name); }
          }}
        />
      )}
      {dropping && <div className="drop-overlay"><div>Drop files or folders to import them</div></div>}
      {managingCategories && (
        <CategoryManager
          categories={categories}
          run={run}
          onChanged={(cats) => {
            setCategories(cats);
            run(refresh);
            // A category renamed or deleted while it's the current view: go to everything.
            if (view.startsWith("cat:") && !cats.some((c) => c.name === view.slice(4))) setView("all");
          }}
          onClose={() => setManagingCategories(false)}
        />
      )}
    </div>
  );
}

export type Run = <T>(call: () => Promise<T>) => Promise<T | undefined>;
