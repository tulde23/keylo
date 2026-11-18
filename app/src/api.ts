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
  /** For a linked secret: where it points and its fields (no values). */
  link: Link | null;
  fileBacked: boolean;
}

export interface LinkedField {
  id: string;
  label: string;
  secret: boolean;
}

export interface VaultEnvironment {
  name: string;
  profile: string | null;
  region: string | null;
  alwaysAsk: boolean;
}

export interface Link {
  provider: string;
  providerName: string;
  title: string;
  where: string | null;
  perEnvironment: boolean;
  fields: LinkedField[];
  mainField: string | null;
  environments: VaultEnvironment[];
  defaultEnvironment: string | null;
}

export interface ProviderSetting {
  key: string;
  description: string;
  value: string | null;
  options: string[] | null;
}

export interface VaultProvider {
  id: string;
  name: string;
  hasEnvironments: boolean;
  pushConfigured: boolean;
  settings: ProviderSetting[];
  environments: VaultEnvironment[];
  defaultEnvironment: string | null;
}

export interface ProviderInput {
  settings: Record<string, string>;
  environments: VaultEnvironment[];
  defaultEnvironment: string | null;
}

export interface ProviderStatus {
  ready: boolean;
  message: string;
}

export interface LinkedItem {
  itemId: string;
  title: string;
  vaultId: string | null;
  vaultName: string | null;
  location: string | null;
  category: string | null;
}

/** Where to search: an AWS environment, or a profile and region (ignored for 1Password). */
export interface LinkScope {
  environment: string | null;
  profile: string | null;
  region: string | null;
}

export interface AwsChoice {
  label: string;
  profile: string | null;
  region: string | null;
  environment: string | null;
}

export interface AwsChoices {
  choices: AwsChoice[];
  regions: string[];
  initial: number;
  initialRegion: string | null;
  cliInstalled: boolean;
  installHint: string;
}

export interface LinkProposal {
  fields: LinkedField[];
  name: string;
  category: string;
}

export interface LinkInput {
  providerId: string;
  scope: LinkScope;
  items: LinkedItem[];
  name: string | null;
  onlyField: string | null;
  category: string | null;
  severalLocations: boolean;
}

export interface PushPreview {
  target: string;
  exists: boolean | null;
}

export interface PushResult {
  name: string;
  succeeded: boolean;
  message: string;
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

export interface ImportItem {
  name: string;
  sourcePath: string;
  category: string | null;
  /** Guessed (in a plan) or used (after importing); null for plain. */
  type: string | null;
  exists: boolean;
}

export interface SkippedFile {
  sourcePath: string;
  reason: string;
}

export interface ImportResult {
  imported: ImportItem[];
  skipped: SkippedFile[];
}

export interface ImportInput {
  paths: string[];
  category: string | null;
  subfolderCategories: boolean;
  overwrite: boolean;
  names: Record<string, string>;
  types: Record<string, string>;
  deleteOriginals: boolean;
}

export interface BackupSummary {
  path: string;
  secrets: number;
  categories: number;
  icons: number;
  bytes: number;
}

export interface BackupPreview {
  path: string;
  createdAt: string;
  secrets: number;
  existing: number;
  categories: number;
  icons: number;
  types: number;
}

export interface RestoreResult {
  added: number;
  replaced: number;
  skipped: number;
  categoriesAdded: number;
  errors: string[];
}

export interface ClaudeStatus {
  registered: boolean;
  command: string | null;
  keyName: string | null;
  keyCovers: string | null;
  hasToken: boolean;
  pointsAt: boolean;
  summary: string;
  cliInstalled: boolean;
  installHint: string;
}

/** latest.json from the newest release, compared with this build. */
export interface UpdateInfo {
  current: string;
  latest: string;
  notes: string | null;
  available: boolean;
  /** Install can update this copy in place; otherwise `reason` says why and the release page is offered. */
  canInstall: boolean;
  reason: string | null;
}

/** The error the backend returns when the session has ended. */
export const LOCKED = "locked";

export const api = {
  appInfo: () => invoke<AppInfo>("app_info"),
  checkUpdate: () => invoke<UpdateInfo>("check_update"),
  installUpdate: () => invoke<void>("install_update"),
  openReleases: () => invoke<void>("open_releases"),
  status: () => invoke<Status>("status"),
  unlock: () => invoke<void>("unlock"),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),
  secrets: () => invoke<Secret[]>("secrets"),
  types: () => invoke<SecretType[]>("secret_types"),
  saveType: (id: string | null, input: TypeInput) => invoke<SecretType[]>("save_type", { id, input }),
  deleteType: (id: string) => invoke<SecretType[]>("delete_type", { id }),
  reveal: (name: string, forEdit = false, environment: string | null = null) =>
    invoke<Record<string, string>>("reveal", { name, forEdit, environment }),
  copy: (name: string, field?: string, environment: string | null = null) =>
    invoke<number>("copy_field", { name, field: field ?? null, environment }),
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
  takeStartupImport: () => invoke<string[]>("take_startup_import"),
  pickImport: (folder: boolean) => invoke<string[]>("pick_import", { folder }),
  importPlan: (paths: string[], category: string | null, subfolderCategories: boolean) =>
    invoke<ImportResult>("import_plan", { paths, category, subfolderCategories }),
  importFiles: (input: ImportInput) => invoke<ImportResult & { deleted: number }>("import_files", { input }),
  pickBackup: (save: boolean) => invoke<string | null>("pick_backup", { save }),
  checkBackupPassword: (password: string) => invoke<string | null>("check_backup_password", { password }),
  createBackup: (path: string, password: string) => invoke<BackupSummary>("create_backup", { path, password }),
  openBackup: (path: string, password: string) => invoke<BackupPreview>("open_backup", { path, password }),
  restoreBackup: (overwrite: boolean) => invoke<RestoreResult>("restore_backup", { overwrite }),
  cancelRestore: () => invoke<void>("cancel_restore"),
  claudeStatus: () => invoke<ClaudeStatus>("claude_status"),
  addToClaude: (token: string) => invoke<void>("add_to_claude", { token }),
  vaultProviders: () => invoke<VaultProvider[]>("vault_providers"),
  saveVaultProvider: (id: string, input: ProviderInput) => invoke<VaultProvider[]>("save_vault_provider", { id, input }),
  vaultStatus: (id: string) => invoke<ProviderStatus>("vault_status", { id }),
  awsChoices: () => invoke<AwsChoices>("aws_choices"),
  linkSearch: (providerId: string, query: string, scope: LinkScope) => invoke<LinkedItem[]>("link_search", { providerId, query, scope }),
  linkDescribe: (providerId: string, item: LinkedItem, scope: LinkScope, severalLocations: boolean) =>
    invoke<LinkProposal>("link_describe", { providerId, item, scope, severalLocations }),
  createLinks: (input: LinkInput) => invoke<{ created: string[]; failed: string[] }>("create_links", { input }),
  pushPreview: (providerId: string, name: string) => invoke<PushPreview>("push_preview", { providerId, name }),
  pushSecret: (providerId: string, name: string) => invoke<PushResult>("push_secret", { providerId, name }),
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
