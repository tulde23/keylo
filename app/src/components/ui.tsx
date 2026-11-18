// Small shared pieces: secret icons, toasts, modals.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Building2, Cloud, CreditCard, Database, FileText, Globe, ImagePlus, KeyRound, LayoutGrid, Link2, Lock, Mail, Server,
  Shield, Smartphone, StickyNote, Terminal, User, Wallet, Wifi, X, type LucideIcon,
} from "lucide-react";
import type { CategorySummary, Secret, SecretType } from "../api";
import { createPortal } from "react-dom";
import { importImageFile, importImageUrl, isImageIcon, useIconImage } from "../iconImages";

// Secrets store Fluent icon names ("Person24") from the C# app; these are the lucide equivalents.
const ICONS: Record<string, LucideIcon> = {
  Person: User, Key: KeyRound, Database, Server, Note: StickyNote, Cloud, Globe, Mail, Lock, Shield,
  Payment: CreditCard, Wallet, Document: FileText, Code: Terminal, WindowConsole: Terminal, Link: Link2,
  Apps: LayoutGrid, LockClosed: Lock, Building: Building2, Phone: Smartphone, Wifi1: Wifi, Wifi,
};

/** Icons to choose from, by the Fluent names the C# app stores (so both apps show the same icon). */
export const ICON_CHOICES = [
  "Key24", "Person24", "Database24", "Server24", "Cloud24", "Globe24", "Mail24", "LockClosed24", "Shield24",
  "Payment24", "Wallet24", "Document24", "Code24", "Building24", "Phone24", "Wifi24", "Note24", "Apps24",
];

/** Accent colours to choose from (stored as #RRGGBB). */
export const COLOR_CHOICES = ["#6366F1", "#0EA5E9", "#10B981", "#84CC16", "#F59E0B", "#F97316", "#EF4444", "#EC4899", "#8B5CF6", "#64748B"];

export function iconFor(name: string | null | undefined): LucideIcon {
  if (!name) return KeyRound;
  const base = name.replace(/\d+$/, "").replace(/(Regular|Filled)$/, "");
  return ICONS[base] ?? KeyRound;
}

/** A secret's icon and colour: its own, else its category's, else its type's. */
export function SecretIcon({ secret, type, category, size = 36 }: {
  secret: Secret; type?: SecretType; category?: CategorySummary; size?: number;
}) {
  const icon = secret.icon ?? (secret.linked ? "Link24" : category?.icon ?? type?.icon ?? null);
  const color = secret.color ?? category?.color ?? type?.color ?? null;
  return <IconTile icon={icon} color={color} size={size} />;
}

/** An icon name drawn at `size`: a built-in symbol, or an uploaded image ("img…"). */
export function IconView({ icon, size, fallback, style }: {
  icon: string | null | undefined; size: number; fallback?: LucideIcon; style?: React.CSSProperties;
}) {
  const image = useIconImage(icon);
  if (isImageIcon(icon)) {
    return image
      ? <img src={image} alt="" width={size} height={size} className="icon-image" style={style} />
      : <span style={{ width: size, height: size, display: "inline-block", ...style }} />;
  }
  const Icon = icon ? iconFor(icon) : fallback ?? KeyRound;
  return <Icon size={size} strokeWidth={2} style={style} />;
}

/** The rounded tile secrets, categories and types show their icon on. Images fill it. */
export function IconTile({ icon, color, size = 36, fallback }: {
  icon: string | null | undefined; color: string | null | undefined; size?: number; fallback?: LucideIcon;
}) {
  const image = isImageIcon(icon);
  return (
    <span
      className={`secret-icon${image ? " has-image" : ""}`}
      style={{ width: size, height: size, ...(color && !image ? { background: color, color: "#fff" } : {}) }}
    >
      <IconView icon={icon} size={image ? size : size * 0.5} fallback={fallback} />
    </span>
  );
}

// ---------------------------------------------------------------------------- toasts

type Toast = { id: number; text: string; error?: boolean };
const ToastContext = createContext<(text: string, error?: boolean) => void>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const show = useCallback((text: string, error = false) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text, error }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), error ? 6000 : 3000);
  }, []);
  return (
    <ToastContext.Provider value={show}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast${t.error ? " toast-error" : ""}`}>{t.text}</div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

// ---------------------------------------------------------------------------- modal

export function Modal({ title, onClose, children, footer, wide }: {
  title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEffect(() => {
    const key = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [onClose]);
  // Rendered on the page itself, so the pane it's opened from can't clip or size it.
  return createPortal(
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-header">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-footer">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

// ---------------------------------------------------------------------------- slide-in panel

/**
 * A full-height panel that slides in from the right, for adding and editing. Header and footer stay
 * put; only the body scrolls. Esc or a click outside closes it, asking first if there are unsaved
 * changes (`dirty`).
 */
export function Drawer({ title, onClose, children, footer, dirty = false }: {
  title: string; onClose: () => void; children: ReactNode; footer: ReactNode; dirty?: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const panel = useRef<HTMLDivElement>(null);
  const requestClose = useCallback(() => (dirty ? setConfirming(true) : onClose()), [dirty, onClose]);

  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      if (confirming) setConfirming(false);
      else requestClose();
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, [confirming, requestClose]);

  // Focus the first field when it opens.
  useEffect(() => {
    panel.current?.querySelector<HTMLElement>("input, textarea, select")?.focus();
  }, []);

  return (
    <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && requestClose()}>
      <aside ref={panel} className="drawer" role="dialog" aria-modal="true" aria-label={title}>
        <header className="drawer-header">
          <h2>{title}</h2>
          <button className="icon-button" onClick={requestClose} aria-label="Close"><X size={18} /></button>
        </header>
        <div className="drawer-body">{children}</div>
        <footer className="drawer-footer">
          {confirming ? (
            <>
              <span className="drawer-confirm">Discard your changes?</span>
              <button className="button" onClick={() => setConfirming(false)} autoFocus>Keep editing</button>
              <button className="button danger-fill" onClick={onClose}>Discard</button>
            </>
          ) : footer}
        </footer>
      </aside>
    </div>
  );
}

// ---------------------------------------------------------------------------- icon and colour pickers

/** Icon choices; `allowDefault` adds a "Default" choice (null: inherit). */
export function IconPicker({ value, onChange, allowDefault }: {
  value: string | null; onChange: (icon: string | null) => void; allowDefault?: boolean;
}) {
  const toast = useToast();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const file = useRef<HTMLInputElement>(null);

  const take = async (work: () => Promise<string>) => {
    setBusy(true);
    try {
      onChange(await work());
      setUrl("");
    } catch (e) {
      toast(e instanceof Error ? e.message : String(e), true);
    } finally {
      setBusy(false);
    }
  };

  // Ctrl+V with an image (or an image address) on the clipboard, anywhere in the picker.
  const onPaste = (e: React.ClipboardEvent) => {
    const image = [...e.clipboardData.items].find((i) => i.kind === "file" && i.type.startsWith("image/"))?.getAsFile();
    if (image) {
      e.preventDefault();
      take(() => importImageFile(image));
      return;
    }
    const text = e.clipboardData.getData("text").trim();
    if (/^(https?:\/\/|data:image\/)/i.test(text) && !(e.target instanceof HTMLInputElement)) {
      e.preventDefault();
      take(() => importImageUrl(text));
    }
  };

  return (
    <div className="icon-picker" onPaste={onPaste}>
    <div className="swatches" role="radiogroup" aria-label="Icon">
      {isImageIcon(value) && (
        <button type="button" role="radio" aria-checked className="icon-swatch active image" aria-label="Your image">
          <IconView icon={value} size={28} />
        </button>
      )}
      {allowDefault && (
        <button type="button" role="radio" aria-checked={value === null} className={`icon-swatch default${value === null ? " active" : ""}`}
          onClick={() => onChange(null)} title="Default (from its category or type)">Auto</button>
      )}
      {ICON_CHOICES.map((choice) => {
        const Icon = iconFor(choice);
        return (
          <button type="button" key={choice} role="radio" aria-checked={value === choice} aria-label={choice.replace(/\d+$/, "")}
            className={`icon-swatch${value === choice ? " active" : ""}`} onClick={() => onChange(choice)}>
            <Icon size={17} />
          </button>
        );
      })}
    </div>
    <div className="image-source">
      <button type="button" className="button small" onClick={() => file.current?.click()} disabled={busy}>
        <ImagePlus size={15} /> Upload image
      </button>
      <input ref={file} type="file" accept="image/*" hidden
        onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) take(() => importImageFile(f)); }} />
      <input className="small-input" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="…or paste an image address"
        aria-label="Image address" disabled={busy}
        onKeyDown={(e) => { if (e.key === "Enter" && url.trim()) { e.preventDefault(); take(() => importImageUrl(url)); } }} />
      <button type="button" className="button small" disabled={busy || !url.trim()} onClick={() => take(() => importImageUrl(url))}>
        {busy ? "Adding…" : "Use"}
      </button>
    </div>
    </div>
  );
}

export function ColorPicker({ value, onChange }: { value: string | null; onChange: (color: string | null) => void }) {
  return (
    <div className="swatches" role="radiogroup" aria-label="Colour">
      <button type="button" role="radio" aria-checked={value === null} aria-label="Default"
        className={`color-swatch none${value === null ? " active" : ""}`} onClick={() => onChange(null)} />
      {COLOR_CHOICES.map((c) => (
        <button type="button" key={c} role="radio" aria-checked={value === c} aria-label={c}
          className={`color-swatch${value === c ? " active" : ""}`} style={{ background: c }} onClick={() => onChange(c)} />
      ))}
    </div>
  );
}

/** A keyboard shortcut as this platform writes it: "⌘K" on a Mac, "Ctrl+K" on Windows and Linux. */
export const IS_MAC = /mac/i.test(navigator.platform || navigator.userAgent);
export function shortcut(key: string) {
  return IS_MAC ? `⌘${key}` : `Ctrl+${key}`;
}
