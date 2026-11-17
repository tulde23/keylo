import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Check, Lock, Search } from "lucide-react";
import { api, type CategorySummary, type AwsChoices, type LinkedItem, type LinkProposal, type LinkScope, type VaultProvider } from "../api";
import type { Run } from "../App";
import { Drawer, useToast } from "./ui";
import CategoryDropdown from "./CategoryDropdown";

/**
 * Links secrets to items in another vault (1Password, AWS Secrets Manager): Keylo keeps only a
 * reference and reads the values from there each time. Pick a vault (for AWS, a profile and region,
 * or an environment to link per environment), search, choose one item or several, and link.
 */
export default function LinkPanel({ categories, run, onClose, onLinked }: {
  categories: CategorySummary[];
  run: Run;
  onClose: () => void;
  onLinked: (firstName: string) => void;
}) {
  const toast = useToast();
  const [providers, setProviders] = useState<VaultProvider[]>([]);
  const [providerId, setProviderId] = useState("1password");
  const [aws, setAws] = useState<AwsChoices | null>(null);
  const [choice, setChoice] = useState(0);
  const [region, setRegion] = useState<string>("");
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<LinkedItem[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [proposal, setProposal] = useState<LinkProposal | null>(null);
  const [describing, setDescribing] = useState(false);
  const [name, setName] = useState("");
  const [category, setCategory] = useState("");
  const [onlyField, setOnlyField] = useState("");
  const [busy, setBusy] = useState(false);

  const provider = providers.find((p) => p.id === providerId);
  const isAws = providerId === "aws";
  const picked = aws?.choices[choice];

  useEffect(() => {
    run(() => api.vaultProviders()).then((p) => p && setProviders(p));
    run(() => api.awsChoices()).then((a) => {
      if (!a) return;
      setAws(a);
      setChoice(a.initial);
      setRegion(a.initialRegion ?? "");
    });
  }, [run]);

  const scope: LinkScope = useMemo(() => {
    if (!isAws || !picked) return { environment: null, profile: null, region: null };
    if (picked.environment) return { environment: picked.environment, profile: null, region: null };
    return { environment: null, profile: picked.profile, region: region || null };
  }, [isAws, picked, region]);

  const search = useCallback(async (text: string) => {
    setSearching(true);
    setProblem(null);
    setSelected([]);
    setProposal(null);
    try {
      setItems(await api.linkSearch(providerId, text, scope));
    } catch (e) {
      setItems(null);
      setProblem(typeof e === "string" ? e : String(e));
    } finally {
      setSearching(false);
    }
  }, [providerId, scope]);

  // Search when the vault or where to look changes (typing searches on Enter). Only when they
  // really change: each search can make 1Password ask for approval.
  const scopeKey = isAws ? JSON.stringify(scope) : "";
  const lastAuto = useRef<string | null>(null);
  useEffect(() => {
    if (isAws && !aws) return;
    const key = `${providerId}|${scopeKey}`;
    if (lastAuto.current === key) return;
    lastAuto.current = key;
    search(query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [providerId, scopeKey, aws]);

  const severalLocations = useMemo(() => new Set((items ?? []).map((i) => i.location)).size > 1, [items]);
  const chosen = (items ?? []).filter((i) => selected.includes(i.itemId));

  // One item chosen: its fields, a name from its title and a suggested category.
  useEffect(() => {
    if (chosen.length !== 1) return setProposal(null);
    let current = true;
    setDescribing(true);
    setProblem(null);
    api.linkDescribe(providerId, chosen[0], scope, severalLocations)
      .then((p) => {
        if (!current) return;
        setProposal(p);
        setName(p.name);
        setCategory((c) => (c === "" || c === proposal?.category ? p.category : c));
        setOnlyField("");
      })
      .catch((e) => current && setProblem(typeof e === "string" ? e : String(e)))
      .finally(() => current && setDescribing(false));
    return () => { current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected.join("|")]);

  const toggle = (id: string) => setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s, id]));

  const link = async () => {
    setBusy(true);
    const outcome = await run(() => api.createLinks({
      providerId,
      scope,
      items: chosen,
      name: chosen.length === 1 ? name.trim() : null,
      onlyField: chosen.length === 1 && onlyField ? onlyField : null,
      category: category.trim() || null,
      severalLocations,
    }));
    setBusy(false);
    if (!outcome) return;
    if (outcome.created.length > 0) onLinked(outcome.created[0]);
    if (outcome.failed.length === 0) {
      toast(outcome.created.length === 1 ? `Linked '${outcome.created[0]}'.` : `Linked ${outcome.created.length} secrets.`);
      onClose();
    } else {
      setProblem(`Linked ${outcome.created.length} of ${chosen.length}. ${outcome.failed.join(" ")}`);
      setSelected([]);
    }
  };

  const canLink = !busy && !describing && (chosen.length > 1 || (chosen.length === 1 && !!proposal && proposal.fields.length > 0 && name.trim() !== ""));
  const waiting = searching || describing || busy;

  return (
    <Drawer
      title="Link from a vault"
      onClose={onClose}
      dirty={selected.length > 0 && !busy}
      footer={<>
        <button className="button" onClick={onClose}>Cancel</button>
        <button className="button primary" disabled={!canLink} onClick={link}>
          {busy ? "Linking…" : chosen.length > 1 ? `Link ${chosen.length} items` : "Link"}
        </button>
      </>}
    >
      <p className="muted">
        A linked secret keeps only a reference: its values are read from the vault each time it's used, so they're never
        copied into Keylo and changes there apply at once.
      </p>

      <div className="type-picker" role="radiogroup" aria-label="Vault">
        {providers.map((p) => (
          <button type="button" key={p.id} role="radio" aria-checked={providerId === p.id}
            className={`type-option${providerId === p.id ? " active" : ""}`} onClick={() => setProviderId(p.id)}>
            {p.name}
          </button>
        ))}
      </div>

      {isAws && aws && (
        <>
          {!aws.cliInstalled && (
            <p className="warning small-text"><AlertTriangle size={14} /> The AWS CLI isn't installed; Keylo reads AWS through it. To install it: {aws.installHint}</p>
          )}
          <div className="form-grid two">
            <label className="form-row">
              <span>Profile or environment</span>
              <select value={choice} onChange={(e) => {
                const i = Number(e.target.value);
                setChoice(i);
                const c = aws.choices[i];
                if (c.region) setRegion(c.region);
              }} aria-label="AWS profile or environment">
                {aws.choices.map((c, i) => <option key={i} value={i}>{c.label}</option>)}
              </select>
            </label>
            <label className="form-row">
              <span>Region</span>
              <select value={picked?.environment ? picked.region ?? "" : region} disabled={!!picked?.environment}
                onChange={(e) => setRegion(e.target.value)} aria-label="AWS region">
                <option value="">{picked?.environment ? "The environment's" : "The profile's"}</option>
                {aws.regions.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </label>
          </div>
          {picked?.environment && (
            <p className="muted small-text">
              Linked from the {picked.environment} environment, a secret is per environment: it's used as NAME@ENV, and each
              environment reads the secret of the same name from its own account.
            </p>
          )}
        </>
      )}

      <form className="link-search" onSubmit={(e) => { e.preventDefault(); search(query); }}>
        <Search size={16} />
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder={`Search ${provider?.name ?? "the vault"}…`}
          aria-label="Search the vault" spellCheck={false} autoFocus />
        <button className="button small" type="submit" disabled={searching}>Search</button>
      </form>

      {waiting && <p className="muted small-text">Waiting for {provider?.name ?? "the vault"}… approve it if it asks.</p>}
      {problem && <p className="bad small-text">{problem}</p>}

      {items && !searching && (
        items.length === 0 ? <p className="muted">Nothing matches.</p> : (
          <>
            <p className="muted small-text">{items.length === 1 ? "1 item" : `${items.length} items`}. Choose one to link, or several.</p>
            <ul className="link-results" role="listbox" aria-multiselectable="true" aria-label="Items">
              {items.map((i) => {
                const on = selected.includes(i.itemId);
                return (
                  <li key={i.itemId} role="option" aria-selected={on} className={on ? "active" : undefined} onClick={() => toggle(i.itemId)}>
                    <span className={`check-box${on ? " on" : ""}`}>{on && <Check size={12} />}</span>
                    <div>
                      <div>{i.title}</div>
                      <small className="muted">{[i.vaultName, i.location, i.category].filter(Boolean).join(" · ")}</small>
                    </div>
                  </li>
                );
              })}
            </ul>
          </>
        )
      )}

      {chosen.length === 1 && proposal && (
        <div className="form link-details">
          <label className="form-row">
            <span>Name in Keylo</span>
            <input value={name} onChange={(e) => setName(e.target.value)} spellCheck={false} maxLength={128} aria-label="Name in Keylo" />
          </label>
          <label className="form-row">
            <span>Fields</span>
            <select value={onlyField} onChange={(e) => setOnlyField(e.target.value)} aria-label="Fields to link">
              <option value="">All fields</option>
              {proposal.fields.map((f) => <option key={f.id} value={f.id}>Only {f.label}{f.secret ? "" : " (not secret)"}</option>)}
            </select>
            <small className="muted">
              {proposal.fields.length === 0 ? "This item has no fields." : proposal.fields.map((f) => f.label).join(", ")}
              {proposal.fields.some((f) => f.secret) && <> · <Lock size={11} /> secret ones are masked and redacted</>}
            </small>
          </label>
        </div>
      )}
      {chosen.length > 1 && (
        <p className="muted">{chosen.length} items, each linked with all its fields and named after its title.</p>
      )}
      {chosen.length > 0 && (
        <div className="form-row">
          <span>Category</span>
          <CategoryDropdown value={category} onChange={setCategory} categories={categories}
            noneLabel={chosen.length > 1 ? "Each item's vault" : "From the vault"} />
        </div>
      )}
    </Drawer>
  );
}
