import { useEffect, useState } from "react";
import { Check } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import type { Run } from "../App";
import { MODES, saveAppearance, THEMES, type Appearance } from "../theme";

/** Settings → Appearance: the colour theme and light/dark, applied and saved as soon as they're picked. */
export default function AppearanceSection({ run }: { run: Run }) {
  const [current, setCurrent] = useState<Appearance | null>(null);

  useEffect(() => {
    invoke<Appearance>("ui_theme").then(setCurrent).catch(() => setCurrent({ theme: "Twilight", mode: "System" }));
  }, []);

  const pick = async (change: Partial<Appearance>) => {
    if (!current) return;
    const next = { ...current, ...change };
    setCurrent(next);
    const saved = await run(() => saveAppearance(next));
    if (saved) setCurrent(saved);
  };

  if (!current) return null;
  return (
    <section className="card">
      <h2>Appearance</h2>
      <p className="muted">Changes right away, here and in the C# Keylo. Not part of Save settings.</p>

      <div className="form-row">
        <span>Theme</span>
        <div className="theme-grid" role="radiogroup" aria-label="Theme">
          {THEMES.map((t) => (
            <button key={t.value} type="button" role="radio" aria-checked={current.theme === t.value}
              className={`theme-option${current.theme === t.value ? " active" : ""}`} onClick={() => pick({ theme: t.value })}>
              <span className="theme-swatch" style={{ background: `linear-gradient(135deg, ${t.swatch[0]}, ${t.swatch[1]})` }}>
                {current.theme === t.value && <Check size={14} />}
              </span>
              <span>
                <strong>{t.label}</strong>
                <small className="muted">{t.description}</small>
              </span>
            </button>
          ))}
        </div>
      </div>

      <div className="form-row">
        <span>Light or dark</span>
        <div className="segmented" role="radiogroup" aria-label="Light or dark">
          {MODES.map((m) => (
            <button key={m.value} type="button" role="radio" aria-checked={current.mode === m.value}
              className={current.mode === m.value ? "active" : undefined} onClick={() => pick({ mode: m.value })}>
              {m.label}
            </button>
          ))}
        </div>
        <small className="muted">Match system follows your OS as it switches.</small>
      </div>
    </section>
  );
}
