import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, LOCKED, message, type AppInfo, type RecentUse, type Secret, type SecretType, type Status } from "./api";
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
    const [list, uses] = await Promise.all([api.secrets(), api.recent()]);
    setSecrets(list);
    setRecent(uses);
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

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of secrets) if (s.category) counts.set(s.category, (counts.get(s.category) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { sensitivity: "base" }));
  }, [secrets]);

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
      />
      {isSecretsView && (
        <>
          <SecretList
            view={view}
            secrets={secrets}
            recent={recent}
            typeOf={typeOf}
            query={query}
            selected={selected}
            onSelect={setSelected}
            onNew={newSecret}
          />
          <SecretDetail
            key={current?.name ?? "none"}
            secret={current}
            type={current ? typeOf(current) : undefined}
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
          categories={categories.map(([c]) => c)}
          run={run}
          onSettingsSaved={async () => setStatus(await api.status())}
        />
      )}
      {editing && (
        <SecretEditor
          secret={editing.secret}
          values={editing.values}
          types={types}
          categories={categories.map(([c]) => c)}
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
    </div>
  );
}

export type Run = <T>(call: () => Promise<T>) => Promise<T | undefined>;
