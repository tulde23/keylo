// Typed wrappers over the Rust commands (src-tauri/src/commands.rs).
import { invoke } from "@tauri-apps/api/core";

export type HelloMode = "session" | "always" | "never";
export type FieldKind = "Text" | "Username" | "Url" | "Number" | "Password" | "SecretText";

export interface AppInfo {
  platform: string;
  verifierName: string;
  storeName: string;
  fileProtection: string;
  version: string;
  dataDir: string;
  keyloPath: string;
}

export interface Status {
  unlocked: boolean;
  mode: HelloMode;
  sessionExpires: string | null;
}

export interface Secret {
  name: string;
  category: string | null;
  username: string | null;
  notes: string | null;
  updatedAt: string;
  size: number;
  icon: string | null;
  color: string | null;
  type: string | null;
  fields: Record<string, string>;
  pinned: boolean;
  linked: boolean;
  fileBacked: boolean;
}

export interface Field {
  id: string;
  label: string;
  kind: FieldKind;
  secret: boolean;
  main: boolean;
  options: string[] | null;
}

export interface SecretType {
  id: string;
  name: string;
  icon: string | null;
  color: string | null;
  builtIn: boolean;
  fields: Field[];
}

export interface CategorySummary {
  name: string;
  count: number;
  icon: string | null;
  color: string | null;
}

export interface RecentUse {
  name: string;
  time: string;
  who: string;
  action: string;
}

export interface Settings {
  hello: HelloMode;
  sessionMinutes: number;
  clipboardSeconds: number;
  auditRetentionDays: number;
}

export type KeyScope = "selected" | "all";

export interface AccessKey {
  id: string;
  name: string;
  scope: KeyScope;
  categories: string[];
  secrets: string[];
  created: string;
  expires: string | null;
  expired: boolean;
}

export interface KeyInput {
  name: string;
  scope: KeyScope;
  categories: string[];
  secrets: string[];
  expiresDays: number | null;
}

export interface AuditRow {
  time: string;
  operation: string;
  secrets: string[];
  key: string | null;
  via: string;
  chain: string[];
}

export interface Approval {
  operation: string;
  secrets: string[];
  keyName: string | null;
  reason: string | null;
  command: string | null;
  canAlwaysAllow: boolean;
  grantOnly: boolean;
  verifierName: string;
}

export interface FieldInput {
  /** "" for a new field; fixed once saved. */
  id: string;
  label: string;
  kind: FieldKind;
  options: string[] | null;
}

export interface TypeInput {
  name: string;
  icon: string | null;
  color: string | null;
  fields: FieldInput[];
}

export interface SaveInput {
  originalName: string | null;
  name: string;
  typeId: string | null;
  fields: Record<string, string>;
  category: string | null;
  notes: string | null;
  icon: string | null;
  color: string | null;
}

/** The error the backend returns when the session has ended. */
export const LOCKED = "locked";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  status: () => invoke<Status>("status"),
  unlock: () => invoke<void>("unlock"),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),
  secrets: () => invoke<Secret[]>("secrets"),
  types: () => invoke<SecretType[]>("secret_types"),
  saveType: (id: string | null, input: TypeInput) => invoke<SecretType[]>("save_type", { id, input }),
  deleteType: (id: string) => invoke<SecretType[]>("delete_type", { id }),
  reveal: (name: string, forEdit = false) => invoke<Record<string, string>>("reveal", { name, forEdit }),
  copy: (name: string, field?: string) => invoke<number>("copy_field", { name, field: field ?? null }),
  save: (input: SaveInput) => invoke<Secret>("save_secret", { input }),
  remove: (name: string) => invoke<void>("delete_secret", { name }),
  setPinned: (name: string, pinned: boolean) => invoke<void>("set_pinned", { name, pinned }),
  recent: () => invoke<RecentUse[]>("recent"),
  categories: () => invoke<CategorySummary[]>("categories"),
  createCategory: (name: string, icon: string | null, color: string | null) =>
    invoke<CategorySummary[]>("create_category", { name, icon, color }),
  setCategoryStyle: (name: string, icon: string | null, color: string | null) =>
    invoke<CategorySummary[]>("set_category_style", { name, icon, color }),
  renameCategory: (from: string, to: string) => invoke<CategorySummary[]>("rename_category", { from, to }),
  deleteCategory: (name: string, moveTo: string | null, deleteSecrets: boolean) =>
    invoke<CategorySummary[]>("delete_category", { name, moveTo, deleteSecrets }),
  settings: () => invoke<Settings>("settings"),
  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),
  keys: () => invoke<AccessKey[]>("access_keys"),
  createKey: (input: KeyInput) => invoke<string>("create_key", { input }),
  updateKey: (id: string, input: KeyInput) => invoke<void>("update_key", { id, input }),
  revokeKey: (id: string) => invoke<void>("revoke_key", { id }),
  audit: (limit: number) => invoke<AuditRow[]>("audit_log", { limit }),
  generatePassword: (length: number, symbols: boolean) => invoke<string>("generate_password", { length, symbols }),
  approval: () => invoke<Approval | null>("approval_request"),
  answerApproval: (choice: "deny" | "once" | "always") => invoke<void>("answer_approval", { choice }),
};

export function message(e: unknown): string {
  return typeof e === "string" ? e : e instanceof Error ? e.message : String(e);
}

export function timeAgo(iso: string): string {
  const seconds = (Date.now() - new Date(iso).getTime()) / 1000;
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  if (seconds < 86400 * 30) return `${Math.floor(seconds / 86400)} d ago`;
  return new Date(iso).toLocaleDateString();
}
