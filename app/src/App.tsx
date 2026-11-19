import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { api, LOCKED, message, type AppInfo, type CategorySummary, type RecentUse, type Secret, type SecretType, type Status } from "./api";
import CategoryManager from "./components/CategoryManager";
import ImportPanel from "./components/ImportPanel";
import LinkPanel from "./components/LinkPanel";
import LockScreen from "./components/LockScreen";
import VaultUnlock from "./components/VaultUnlock";
import Sidebar, { type View } from "./components/Sidebar";
import SecretList from "./components/SecretList";
import SecretDetail from "./components/SecretDetail";
import SecretEditor from "./components/SecretEditor";
import SettingsView from "./components/SettingsView";
import ActivityView from "./components/ActivityView";
import Footer from "./components/Footer";
import TopBar from "./components/TopBar";
import UpdateNotice from "./components/UpdateNotice";
import { ToastProvider, useToast } from "./components/ui";

export default function App() {
  return (
    <ToastProvider>
      <Shell />
      <UpdateNotice />
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
  const [settingsOpen, setSettingsOpen] = useState(false);
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

  // Changes made outside the window (the keylo command, an agent, another Keylo) show up when the
  // window comes back into focus, or when Keylo's files change. Quietly: no toasts if it fails.
  const [dataVersion, setDataVersion] = useState(0);
  const reloadTimer = useRef<number | undefined>(undefined);
  const reloadFromOutside = useCallback(() => {
    window.clearTimeout(reloadTimer.current);
    reloadTimer.current = window.setTimeout(async () => {
      try {
        const s = await api.status();
        setStatus(s);
        if (!s.unlocked) return;
        await refresh();
        setTypes(await api.types());
        setDataVersion((v) => v + 1);
      } catch {
        // Locked or busy: the next change or focus tries again.
      }
    }, 300);
  }, [refresh]);
  useEffect(() => {
    const focus = getCurrentWindow().onFocusChanged(({ payload: focused }) => { if (focused) reloadFromOutside(); });
    const files = listen("keylo://data-changed", reloadFromOutside);
    return () => { focus.then((f) => f()); files.then((f) => f()); };
  }, [reloadFromOutside]);

  // Reload on unlock, and when Settings opens (it counts secrets per type; the CLI may have added some).
  useEffect(() => {
    if (status?.unlocked) run(refresh);
  }, [status?.unlocked, refresh, run]);
  useEffect(() => {
    if (settingsOpen && status?.unlocked) run(refresh);
  }, [settingsOpen, status?.unlocked, refresh, run]);
  // Locking closes Settings; unlocking starts back at the secrets.
  useEffect(() => {
    if (status && !status.unlocked) setSettingsOpen(false);
  }, [status]);

  // Esc clears the selection (back to "Select a secret"), unless something else wants it.
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      const typing = e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement || e.target instanceof HTMLSelectElement;
      if (typing || document.querySelector(".drawer-backdrop, .modal-backdrop, .settings-backdrop")) return;
      setSelected(null);
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);

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

  const current = secrets.find((s) => s.name === selected) ?? null;

  if (!info || !status) return <div className="splash" />;
  if (status.vaultLocked) {
    return <VaultUnlock info={info} onUnlocked={async () => setStatus(await api.status())} />;
  }
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
        onImport={async (folder) => {
          const picked = await run(() => api.pickImport(folder));
          if (picked?.length) addImports(picked);
        }}
        onLink={() => setLinking(true)}
        onSettings={() => setSettingsOpen(!settingsOpen)}
        onActivity={() => { setSettingsOpen(false); setView("activity"); setQuery(""); setSelected(null); }}
        activityActive={view === "activity" && !settingsOpen}
        onLock={lock}
        settingsActive={settingsOpen}
        lockTitle={lockTitle}
      />
      <Sidebar
        view={view}
        onView={(v) => { setView(v); setQuery(""); setSelected(null); }}
        categories={categories}
        types={types}
        secrets={secrets}
        onManageCategories={() => setManagingCategories(true)}
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
            autoRefreshCodes={status.mode !== "always"}
            onEdit={(values) => current && setEditing({ secret: current, values })}
            onChanged={async (name) => {
              await run(refresh);
              if (name !== undefined) setSelected(name);
            }}
          />
        </>
      )}
      {view === "activity" && <ActivityView run={run} version={dataVersion} />}
      <Footer info={info} />
      {settingsOpen && (
        <SettingsView
          info={info}
          secrets={secrets}
          types={types}
          onTypes={setTypes}
          categories={categories}
          run={run}
          onSettingsSaved={async () => setStatus(await api.status())}
          onDataChanged={() => { run(refresh); api.types().then(setTypes).catch(() => {}); }}
          onClose={() => setSettingsOpen(false)}
          version={dataVersion}
        />
      )}
      {editing && (
        <SecretEditor
          secret={editing.secret}
          values={editing.values}
          types={types}
          categories={categories}
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
          categories={categories}
          run={run}
          onClose={() => setImporting(null)}
          onImported={() => run(refresh)}
        />
      )}
      {linking && (
        <LinkPanel
          categories={categories}
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
