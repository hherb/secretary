// Discriminator strings match the Rust side's
// `#[serde(tag = "code", rename_all = "snake_case")]` wire format.
// Adding a Rust variant without extending the union here breaks
// `userMessageFor`'s exhaustive switch at tsc compile time;
// `userMessageFor` also has a runtime default arm in case a future
// build's wire format precedes the matching TS source update.

// Single source of truth for known AppError discriminator strings. Exported
// so runtime guards (e.g. `ipc.ts::isAppError`) can validate against the
// same set the type union uses. Adding/removing an entry here forces the
// `AppError` union below to be edited in lockstep — both feed
// `userMessageFor`'s exhaustive switch.
export const APP_ERROR_CODES = [
  'vault_path_not_found',
  'vault_path_not_a_vault',
  'vault_path_locked',
  'wrong_password',
  'kdf_too_weak',
  'vault_corrupt',
  'already_unlocked',
  'not_unlocked',
  'settings_corrupt',
  'settings_unknown_version',
  'settings_out_of_range',
  'io',
  'internal'
] as const;
export type AppErrorCode = (typeof APP_ERROR_CODES)[number];

export const APP_WARNING_CODES = [
  'settings_corrupt',
  'settings_clamped',
  'settings_unknown_version'
] as const;
export type AppWarningCode = (typeof APP_WARNING_CODES)[number];

export type AppError =
  | { code: 'vault_path_not_found'; path: string }
  | { code: 'vault_path_not_a_vault'; path: string }
  | { code: 'vault_path_locked'; path: string }
  | { code: 'wrong_password' }
  | { code: 'kdf_too_weak'; current_memory_kib: number; min_memory_kib: number }
  | { code: 'vault_corrupt' }
  | { code: 'already_unlocked' }
  | { code: 'not_unlocked' }
  | { code: 'settings_corrupt' }
  | { code: 'settings_unknown_version'; version: string }
  | { code: 'settings_out_of_range'; min: number; max: number }
  | { code: 'io' }
  | { code: 'internal' };

export type AppWarning =
  | { code: 'settings_corrupt' }
  | { code: 'settings_clamped'; original_ms: number; clamped_ms: number }
  | { code: 'settings_unknown_version'; version: string };

export interface UserMessage {
  title: string;
  detail?: string;
  actionHint?: string;
}

const MS_PER_SECOND = 1_000;

export function userMessageFor(err: AppError): UserMessage {
  switch (err.code) {
    case 'vault_path_not_found':
      return {
        title: 'Folder not found',
        detail: err.path,
        actionHint: 'Check the path or choose a different folder.'
      };
    case 'vault_path_not_a_vault':
      return {
        title: 'Not a vault',
        detail: `${err.path} doesn't contain a vault manifest.`,
        actionHint: 'Did you mean to create a new vault here?'
      };
    case 'vault_path_locked':
      return {
        title: 'Vault in use',
        detail: 'Another Secretary instance or sync daemon is holding the lock.',
        actionHint: 'Close the other application and try again.'
      };
    case 'wrong_password':
      return {
        title: 'Wrong password',
        actionHint: 'Check Caps Lock and keyboard layout.'
      };
    case 'kdf_too_weak':
      return {
        title: 'Vault is too weakly protected',
        detail: `Uses ${err.current_memory_kib} KiB of KDF memory; minimum is ${err.min_memory_kib} KiB.`,
        actionHint: 'This vault may have been created with an old version. Contact support.'
      };
    case 'vault_corrupt':
      return {
        title: 'Vault appears corrupted',
        actionHint: 'Restore from a recent backup.'
      };
    case 'already_unlocked':
      return { title: 'Vault already unlocked' };
    case 'not_unlocked':
      return { title: 'Vault is locked' };
    case 'settings_corrupt':
      return {
        title: 'Settings malformed',
        detail: 'Using default values.',
        actionHint: 'Change a setting to overwrite the corrupt record.'
      };
    case 'settings_unknown_version':
      return {
        title: 'Settings format newer than this app',
        detail: `Schema version "${err.version}" is from a newer Secretary build. Using defaults.`
      };
    case 'settings_out_of_range':
      return {
        title: 'Value out of range',
        detail: `Auto-lock timeout must be between ${err.min / MS_PER_SECOND}s and ${err.max / MS_PER_SECOND}s.`
      };
    case 'io':
      return {
        title: 'Filesystem error',
        actionHint: 'Check disk space and permissions, then try again.'
      };
    case 'internal':
      return {
        title: 'Internal error',
        actionHint: 'This is a bug. Please report it.'
      };
    default:
      return unknownErrorFallback(err);
  }
}

// Runtime fallback for `code` values not in the union — defends against a
// future-Rust variant whose TS counterpart hasn't shipped yet. The compile-
// time exhaustiveness check on the switch above is the primary gate; this
// arm ensures the runtime cost of a miss is a logged "Unknown error" toast,
// not a blank one (toast renderer would deref `.title` of `undefined`).
function unknownErrorFallback(err: AppError): UserMessage {
  console.error('userMessageFor: unknown AppError code', err);
  return {
    title: 'Unknown error',
    detail: `code="${(err as { code: string }).code}"`,
    actionHint: 'This may indicate an outdated app — try updating.'
  };
}

export function userMessageForWarning(w: AppWarning): UserMessage {
  switch (w.code) {
    case 'settings_corrupt':
      return {
        title: 'Settings record malformed',
        detail: 'Using default values until you change a setting.'
      };
    case 'settings_clamped':
      return {
        title: 'Settings value clamped',
        detail: `Auto-lock changed from ${w.original_ms / MS_PER_SECOND}s to ${w.clamped_ms / MS_PER_SECOND}s (within allowed bounds).`
      };
    case 'settings_unknown_version':
      return {
        title: 'Settings format newer than this app',
        detail: `Schema "${w.version}" — using defaults.`
      };
    default:
      console.error('userMessageForWarning: unknown AppWarning code', w);
      return {
        title: 'Unknown warning',
        detail: `code="${(w as { code: string }).code}"`
      };
  }
}
