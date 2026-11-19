// The colour theme and light/dark mode (Settings → Appearance), kept in
// ui.json. Applied as data attributes on <html>; the colours are in themes.css.
import { invoke } from "@tauri-apps/api/core";

export type ThemeName = "QuietViolet" | "Graphite" | "Ocean" | "Evergreen" | "Ember";
export type ThemeMode = "System" | "Light" | "Dark";
export interface Appearance {
  theme: ThemeName;
  mode: ThemeMode;
}

export const THEMES: { value: ThemeName; label: string; description: string; swatch: [string, string] }[] = [
  { value: "QuietViolet", label: "Quiet violet", description: "Near-neutral greys; violet only where it matters. The default.", swatch: ["#6D28D9", "#A78BFA"] },
  { value: "Graphite", label: "Graphite", description: "Plain greys, no colour at all.", swatch: ["#27272A", "#71717A"] },
  { value: "Ocean", label: "Ocean", description: "Cool grey-blue surfaces with blue accents.", swatch: ["#1D4ED8", "#60A5FA"] },
  { value: "Evergreen", label: "Evergreen", description: "Soft green-grey surfaces with emerald accents.", swatch: ["#065F46", "#34D399"] },
  { value: "Ember", label: "Ember", description: "Warm stone surfaces with burnt-orange accents.", swatch: ["#9A3412", "#FB923C"] },
];

const DEFAULT: Appearance = { theme: "QuietViolet", mode: "System" };

export const MODES: { value: ThemeMode; label: string }[] = [
  { value: "System", label: "Match system" },
  { value: "Light", label: "Light" },
  { value: "Dark", label: "Dark" },
];

const CACHE = "keylo-appearance";

export function applyAppearance(a: Appearance) {
  if (!THEMES.some((t) => t.value === a.theme)) a = { ...a, theme: DEFAULT.theme };
  document.documentElement.dataset.theme = a.theme.toLowerCase();
  document.documentElement.dataset.mode = a.mode.toLowerCase();
  try {
    localStorage.setItem(CACHE, JSON.stringify(a));
  } catch {
    // Storage can be unavailable; the theme still applies.
  }
}

/** The last theme used, at once (no flash of the default), then the saved one from ui.json. */
export function initAppearance() {
  try {
    const cached = localStorage.getItem(CACHE);
    applyAppearance(cached ? (JSON.parse(cached) as Appearance) : DEFAULT);
  } catch {
    applyAppearance(DEFAULT);
  }
  invoke<Appearance>("ui_theme").then(applyAppearance).catch(() => {});
}

export async function saveAppearance(a: Appearance): Promise<Appearance> {
  applyAppearance(a);
  const saved = await invoke<Appearance>("set_ui_theme", { theme: a.theme, mode: a.mode });
  applyAppearance(saved);
  return saved;
}
