import { useEffect, useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { api, type ProviderStatus, type VaultEnvironment, type VaultProvider } from "../api";
import type { Run } from "../App";
import { useToast } from "./ui";

const settingLabel = (key: string) =>
  ({ kms_key_id: "KMS key ID" } as Record<string, string>)[key] ?? key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, " ");

const looksLikeProduction = (name: string) => /^(prod|production|prd)$|^prod-/i.test(name);

/**
 * Settings → Vault providers: what pushing uses (1Password vault, AWS profile and region…) and,
 * for AWS, the environments per-environment links read from (each a profile and region on this
 * computer). Saving asks for the identity check, since "always ask" decides what agents may use.
 */
export default function VaultsSection({ run, verifierName }: { run: Run; verifierName: string }) {
  const [providers, setProviders] = useState<VaultProvider[] | null>(null);
  useEffect(() => {
    run(() => api.vaultProviders()).then((p) => p && setProviders(p));
  }, [run]);

  return (
    <section className="card">
      <h2>Vault providers</h2>
      <p className="muted">
        Secrets can be linked to items in these vaults (Link in the top bar) and pushed into them. Keylo uses their command-line
        tools (<code>op</code> and <code>aws</code>) and keeps none of their credentials.
      </p>
      {providers?.map((p) => (
        <ProviderEditor key={p.id} provider={p} run={run} verifierName={verifierName} onSaved={setProviders} />
      ))}
    </section>
  );
}

function ProviderEditor({ provider, run, verifierName, onSaved }: {
  provider: VaultProvider;
  run: Run;
  verifierName: string;
  onSaved: (all: VaultProvider[]) => void;
}) {
  const toast = useToast();
  const initial = () => ({
    settings: Object.fromEntries(provider.settings.map((s) => [s.key, s.value ?? ""])) as Record<string, string>,
    environments: provider.environments,
    defaultEnvironment: provider.defaultEnvironment,
  });
  const [draft, setDraft] = useState(initial);
  const [status, setStatus] = useState<ProviderStatus | null>(null);
  const [checking, setChecking] = useState(false);
  useEffect(() => setDraft(initial()), [provider]); // eslint-disable-line react-hooks/exhaustive-deps

  const dirty = JSON.stringify(draft) !== JSON.stringify(initial());
  const profiles = provider.settings.find((s) => s.key === "profile")?.options ?? [];
  const regions = provider.settings.find((s) => s.key === "region")?.options ?? [];

  const setEnv = (i: number, change: Partial<VaultEnvironment>) =>
    setDraft((d) => ({ ...d, environments: d.environments.map((e, j) => (j === i ? { ...e, ...change } : e)) }));
  const addEnv = () => {
    const taken = new Set(draft.environments.map((e) => e.name.toLowerCase()));
    const name = ["dev", "uat", "prod"].find((n) => !taken.has(n)) ?? "";
    setDraft((d) => ({ ...d, environments: [...d.environments, { name, profile: null, region: null, alwaysAsk: looksLikeProduction(name) }] }));
  };
  const removeEnv = (i: number) =>
    setDraft((d) => {
      const removed = d.environments[i];
      return {
        ...d,
        environments: d.environments.filter((_, j) => j !== i),
        defaultEnvironment: d.defaultEnvironment === removed.name ? null : d.defaultEnvironment,
      };
    });

  const save = async () => {
    const all = await run(() => api.saveVaultProvider(provider.id, {
      settings: draft.settings,
      environments: draft.environments.map((e) => ({ ...e, name: e.name.trim(), profile: e.profile?.trim() || null, region: e.region?.trim() || null })),
      defaultEnvironment: draft.defaultEnvironment,
    }));
    if (all) {
      onSaved(all);
      toast(`${provider.name} saved.`);
      setStatus(null);
    }
  };

  const check = async () => {
    setChecking(true);
    const s = await run(() => api.vaultStatus(provider.id));
    setChecking(false);
    if (s) setStatus(s);
  };

  return (
    <div className="provider">
      <h3>{provider.name}</h3>
      <div className="form-grid">
        {provider.settings.map((s) => (
          <label className="form-row" key={s.key}>
            <span>{settingLabel(s.key)}</span>
            <input
              value={draft.settings[s.key] ?? ""}
              onChange={(e) => setDraft((d) => ({ ...d, settings: { ...d.settings, [s.key]: e.target.value } }))}
              list={s.options ? `${provider.id}-${s.key}` : undefined}
              spellCheck={false}
              aria-label={`${provider.name} ${s.key}`}
            />
            {s.options && <datalist id={`${provider.id}-${s.key}`}>{s.options.map((o) => <option key={o} value={o} />)}</datalist>}
            <small className="muted">{s.description}</small>
          </label>
        ))}
      </div>

      {provider.hasEnvironments && (
        <div className="environments">
          <h4>Environments</h4>
          <p className="muted small-text">
            Secrets linked per environment are used as NAME@ENV (orders-db@uat); each environment reads from its own profile and
            region on this computer. Agents always need your approval for an environment marked “always ask”, whatever their key
            covers.
          </p>
          {draft.environments.length > 0 && (
            <table className="env-table">
              <thead><tr><th>Name</th><th>Profile</th><th>Region</th><th>Always ask</th><th>Default</th><th /></tr></thead>
              <tbody>
                {draft.environments.map((e, i) => (
                  <tr key={i}>
                    <td>
                      <input value={e.name} maxLength={32} spellCheck={false} aria-label="Environment name"
                        onChange={(x) => {
                          const name = x.target.value;
                          const wasDefault = draft.defaultEnvironment === e.name;
                          setEnv(i, { name, ...(looksLikeProduction(name) && !looksLikeProduction(e.name) ? { alwaysAsk: true } : {}) });
                          if (wasDefault) setDraft((d) => ({ ...d, defaultEnvironment: name }));
                        }} />
                    </td>
                    <td>
                      <input value={e.profile ?? ""} list={`${provider.id}-profiles`} placeholder="default credentials" spellCheck={false}
                        aria-label={`Profile for ${e.name}`} onChange={(x) => setEnv(i, { profile: x.target.value || null })} />
                    </td>
                    <td>
                      <input value={e.region ?? ""} list={`${provider.id}-regions`} placeholder="the profile's" spellCheck={false}
                        aria-label={`Region for ${e.name}`} onChange={(x) => setEnv(i, { region: x.target.value || null })} />
                    </td>
                    <td className="center">
                      <input type="checkbox" checked={e.alwaysAsk} aria-label={`Always ask for ${e.name}`}
                        onChange={(x) => setEnv(i, { alwaysAsk: x.target.checked })} />
                    </td>
                    <td className="center">
                      <input type="radio" name={`${provider.id}-default`} checked={draft.defaultEnvironment === e.name}
                        aria-label={`${e.name} is the default`} onChange={() => setDraft((d) => ({ ...d, defaultEnvironment: e.name }))} />
                    </td>
                    <td>
                      <button className="icon-button small" onClick={() => removeEnv(i)} aria-label={`Remove ${e.name}`}><Trash2 size={14} /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <datalist id={`${provider.id}-profiles`}>{profiles.map((o) => <option key={o} value={o} />)}</datalist>
          <datalist id={`${provider.id}-regions`}>{regions.map((o) => <option key={o} value={o} />)}</datalist>
          <button className="button small" onClick={addEnv}><Plus size={14} /> Add environment</button>
          {draft.environments.length > 1 && !draft.defaultEnvironment && (
            <p className="muted small-text">No default: NAME without @ENV won't work until you choose one.</p>
          )}
        </div>
      )}

      <div className="form-actions start">
        <button className="button primary" disabled={!dirty} onClick={save}>Save</button>
        <button className="button" disabled={checking} onClick={check}>{checking ? "Checking…" : "Check push setup"}</button>
        {status && <span className={status.ready ? "ok small-text" : "bad small-text"}>{status.message}</span>}
      </div>
      {dirty && <p className="muted small-text">Saving asks for {verifierName}.</p>}
    </div>
  );
}
