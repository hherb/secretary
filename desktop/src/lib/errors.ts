// Discriminated union mirroring src-tauri/src/errors.rs::AppError and
// ::AppWarning. The Rust side serializes with
// `#[serde(tag = "code", rename_all = "snake_case")]`; the discriminator
// strings below MUST match exactly. Adding a Rust variant without
// extending this union surfaces as a TypeScript-side fall-through where
// the switch in `userMessageFor` no longer covers every code path — keep
// the two in lockstep.

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
  }
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
  }
}
