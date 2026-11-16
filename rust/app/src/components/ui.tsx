// Small shared pieces: secret icons, toasts, modals.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import {
  Cloud, CreditCard, Database, FileText, Globe, KeyRound, Link2, Lock, Mail, Server, Shield, StickyNote,
  Terminal, User, Wallet, X, type LucideIcon,
} from "lucide-react";
import type { Secret, SecretType } from "../api";

// Secrets store Fluent icon names ("Person24") from the C# app; these are the lucide equivalents.
const ICONS: Record<string, LucideIcon> = {
  Person: User, Key: KeyRound, Database, Server, Note: StickyNote, Cloud, Globe, Mail, Lock, Shield,
  Payment: CreditCard, Wallet, Document: FileText, Code: Terminal, WindowConsole: Terminal, Link: Link2,
};

export function iconFor(name: string | null | undefined): LucideIcon {
  if (!name) return KeyRound;
  const base = name.replace(/\d+$/, "").replace(/(Regular|Filled)$/, "");
  return ICONS[base] ?? KeyRound;
}

export function SecretIcon({ secret, type, size = 36 }: { secret: Secret; type?: SecretType; size?: number }) {
  const Icon = secret.linked ? Link2 : iconFor(secret.icon ?? type?.icon);
  const color = secret.color ?? type?.color ?? null;
  return (
    <span
      className="secret-icon"
      style={{ width: size, height: size, ...(color ? { background: color, color: "#fff" } : {}) }}
    >
      <Icon size={size * 0.5} strokeWidth={2} />
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
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal${wide ? " modal-wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <header className="modal-header">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="Close"><X size={18} /></button>
        </header>
        <div className="modal-body">{children}</div>
        {footer && <footer className="modal-footer">{footer}</footer>}
      </div>
    </div>
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
