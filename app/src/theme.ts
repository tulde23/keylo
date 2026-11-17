// The colour theme and light/dark mode (Settings → Appearance), shared with the C# app through
// ui.json. Applied as data attributes on <html>; the colours are in themes.css.
import { invoke } from "@tauri-apps/api/core";

export type ThemeName = "Twilight" | "QuietViolet" | "Aurora";
export type ThemeMode = "System" | "Light" | "Dark";
export interface Appearance {
  theme: ThemeName;
  mode: ThemeMode;
}

export const THEMES: { value: ThemeName; label: string; description: string; swatch: [string, string] }[] = [
  { value: "Twilight", label: "Twilight", description: "Violet-tinted surfaces and the logo's gradient. The default.", swatch: ["#9333EA", "#5B21B6"] },
  { value: "QuietViolet", label: "Quiet violet", description: "Near-neutral greys; violet only where it matters.", swatch: ["#6D28D9", "#A78BFA"] },
  { value: "Aurora", label: "Aurora", description: "Neutral surfaces with orchid and violet accents.", swatch: ["#9333EA", "#C084FC"] },
];

export const MODES: { value: ThemeMode; label: string }[] = [
  { value: "System", label: "Match system" },
  { value: "Light", label: "Light" },
  { value: "Dark", label: "Dark" },
];

const CACHE = "keylo-appearance";

export function applyAppearance(a: Appearance) {
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
    applyAppearance(cached ? (JSON.parse(cached) as Appearance) : { theme: "Twilight", mode: "System" });
  } catch {
    applyAppearance({ theme: "Twilight", mode: "System" });
  }
  invoke<Appearance>("ui_theme").then(applyAppearance).catch(() => {});
}

export async function saveAppearance(a: Appearance): Promise<Appearance> {
  applyAppearance(a);
  const saved = await invoke<Appearance>("set_ui_theme", { theme: a.theme, mode: a.mode });
  applyAppearance(saved);
  return saved;
}
