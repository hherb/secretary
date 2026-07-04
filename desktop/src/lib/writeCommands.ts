/**
 * Source of truth for the desktop write-reauth gate-coverage test (#280).
 *
 * Every Tauri command registered in `src-tauri/src/main.rs`'s `generate_handler!`
 * is classified here exactly once, keyed by the command string (the token shared
 * by both the Rust ident and the `ipc.ts` `call<…>('cmd', …)` wrapper). Adding a
 * command in Rust without a matching entry here fails the coverage test — forcing
 * a conscious read / write-gated / write-exempt / session decision.
 *
 * The gate is a presence-assurance UX layer for an unlocked-but-unattended session,
 * NOT a hard trust boundary (#278/#280). `exempt` writes record *why* they need no
 * call-site gate.
 */

export type CommandKind = 'read' | 'write' | 'session';
export type GateDisposition = 'gated' | 'exempt';

export interface CommandClass {
  /** Command category. `gate`/`wrapper`/`reason` apply only when `kind === 'write'`. */
  kind: CommandKind;
  /** Whether a mutating write is gated at its call site or explicitly exempt. */
  gate?: GateDisposition;
  /** The exported `ipc.ts` wrapper function name (writes only). */
  wrapper?: string;
  /** Justification — REQUIRED when `gate === 'exempt'`. */
  reason?: string;
}

export const COMMAND_CLASSIFICATION: Record<string, CommandClass> = {
  // --- writes: gated at the Svelte call site (#278) ---
  set_settings: { kind: 'write', gate: 'gated', wrapper: 'setSettings' },
  create_block: { kind: 'write', gate: 'gated', wrapper: 'createBlock' },
  rename_block: { kind: 'write', gate: 'gated', wrapper: 'renameBlock' },
  save_record: { kind: 'write', gate: 'gated', wrapper: 'saveRecord' },
  save_record_edit: { kind: 'write', gate: 'gated', wrapper: 'saveRecordEdit' },
  move_record: { kind: 'write', gate: 'gated', wrapper: 'moveRecord' },
  tombstone_record: { kind: 'write', gate: 'gated', wrapper: 'tombstoneRecord' },
  resurrect_record: { kind: 'write', gate: 'gated', wrapper: 'resurrectRecord' },
  trash_block: { kind: 'write', gate: 'gated', wrapper: 'trashBlock' },
  restore_block: { kind: 'write', gate: 'gated', wrapper: 'restoreBlock' },
  import_contact: { kind: 'write', gate: 'gated', wrapper: 'importContact' },
  share_block: { kind: 'write', gate: 'gated', wrapper: 'shareBlock' },
  revoke_block_from: { kind: 'write', gate: 'gated', wrapper: 'revokeBlockFrom' },
  delete_contact_card: { kind: 'write', gate: 'gated', wrapper: 'deleteContactCard' },

  // --- writes: exempt, with recorded reason ---
  create_vault: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'createVault',
    reason: 'pre-unlock bootstrap — no unlocked session to protect',
  },
  probe_create_target: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'probeCreateTarget',
    reason: 'pre-unlock probe of a target folder; performs no vault mutation',
  },
  sync_now: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'syncNow',
    reason: 'takes the vault password directly — re-auth is intrinsic',
  },
  sync_commit_decisions: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'syncCommitDecisions',
    reason: 'takes the vault password directly — re-auth is intrinsic',
  },
  pick_vault_folder: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'pickVaultFolder',
    reason:
      'opens a native dialog and records the chosen path in a backend PathPurpose slot (#353); performs no vault mutation',
  },
  pick_create_folder: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'pickCreateFolder',
    reason:
      'opens a native dialog and records the chosen path in the backend CreateParent slot (#378); performs no vault mutation — kept separate from pick_vault_folder so an unlock pick never authorizes a create',
  },
  pick_contact_card: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'pickContactCard',
    reason:
      'opens a native dialog and records the chosen path in a backend PathPurpose slot (#353); the gated import_contact call consumes it, not the picker',
  },
  pick_export_dir: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'pickExportDir',
    reason:
      'opens a native dialog and records the chosen path in a backend PathPurpose slot (#353); performs no vault mutation',
  },
  repair_vault: {
    kind: 'write',
    gate: 'exempt',
    wrapper: 'repairVault',
    reason:
      'pre-unlock crash-recovery path invoked from the locked Unlock screen (mirrors unlock_with_password) — takes the vault password directly and there is no unlocked session yet to protect',
  },

  // --- session / auth ---
  unlock_with_password: { kind: 'session' },
  lock: { kind: 'session' },
  notify_activity: { kind: 'session' },
  verify_password: { kind: 'session' },

  // --- reads ---
  list_blocks: { kind: 'read' },
  get_manifest: { kind: 'read' },
  get_settings: { kind: 'read' },
  read_block: { kind: 'read' },
  reveal_field: { kind: 'read' },
  reveal_record: { kind: 'read' },
  list_trashed_blocks: { kind: 'read' },
  list_contacts: { kind: 'read' },
  export_contact_card: { kind: 'read' },
  block_recipients: { kind: 'read' },
  list_contact_blocks: { kind: 'read' },
  sync_status: { kind: 'read' },
};

/** Set of every classified command string. */
export function classifiedCommandNames(): Set<string> {
  return new Set(Object.keys(COMMAND_CLASSIFICATION));
}

/** Wrapper names of writes that must be gated at their call site. */
export function gatedWrappers(): string[] {
  return Object.values(COMMAND_CLASSIFICATION)
    .filter((c) => c.gate === 'gated' && c.wrapper)
    .map((c) => c.wrapper as string);
}

/** Command strings of exempt writes that fail to record a reason (should be empty). */
export function exemptWritesMissingReason(): string[] {
  return Object.entries(COMMAND_CLASSIFICATION)
    .filter(([, c]) => c.gate === 'exempt' && !c.reason?.trim())
    .map(([cmd]) => cmd);
}
