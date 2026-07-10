// Typed wrappers around Tauri's invoke(). One function per backend command
// exposed by src-tauri/src/commands/. All catch IPC errors and re-throw a
// typed AppError union from errors.ts so callers can use exhaustive
// pattern-matching at the UI layer rather than ad-hoc `instanceof` checks.
//
// The Rust side uses `#[serde(rename_all = "camelCase")]` on DTOs and
// `#[serde(tag = "code", rename_all = "snake_case")]` on AppError/AppWarning;
// Tauri 2's IPC layer additionally converts snake_case Rust command
// arguments to camelCase on the JS side, so we send `folderPath` here
// for the Rust `folder_path: String` parameter.

import { invoke } from '@tauri-apps/api/core';
import { APP_ERROR_CODES, type AppError, type AppErrorCode, type AppWarning } from './errors';
import type { SyncStatusDto, SyncOutcome, VetoDecisionDto } from './sync';

const KNOWN_ERROR_CODES: ReadonlySet<AppErrorCode> = new Set(APP_ERROR_CODES);

export interface BlockSummaryDto {
  blockUuidHex: string;
  blockName: string;
  createdAtMs: number;
  lastModifiedMs: number;
}

export interface ManifestDto {
  vaultUuidHex: string;
  ownerUserUuidHex: string;
  blockCount: number;
  blockSummaries: BlockSummaryDto[];
  warnings: AppWarning[];
}

export interface SettingsDto {
  autoLockTimeoutMs: number;
  requirePasswordBeforeEdits: boolean;
  reauthGraceWindowMs: number;
  retentionWindowMs: number;
}

export interface FieldMetaDto {
  name: string;
  lastModMs: number;
  isText: boolean;
  isBytes: boolean;
}

export interface RecordDto {
  recordUuidHex: string;
  recordType: string;
  tags: string[];
  createdAtMs: number;
  lastModMs: number;
  fieldCount: number;
  fields: FieldMetaDto[];
  tombstoned?: boolean;
}

export interface BlockDetailDto {
  blockUuidHex: string;
  blockName: string;
  records: RecordDto[];
}

export interface TrashedBlockDto {
  blockUuidHex: string;
  blockName: string;
  tombstonedAtMs: number;
  tombstonedByHex: string;
}

export interface ExpiredEntryDto {
  blockUuidHex: string;
  tombstonedAtMs: number;
  ageMs: number;
}

export interface RetentionPreviewDto {
  entries: ExpiredEntryDto[];
  windowMs: number;
}

export interface RetentionReportDto {
  purgedCount: number;
  sharedCount: number;
  ownerOnlyCount: number;
  unknownCount: number;
  filesRemoved: number;
  filesFailed: number;
  windowMs: number;
}

export interface PurgeReportDto {
  blockUuidHex: string;
  wasShared: boolean | null;
  recipientCount: number | null;
  filesRemoved: number;
}

export interface EmptyTrashReportDto {
  purgedCount: number;
  sharedCount: number;
  ownerOnlyCount: number;
  unknownCount: number;
  filesRemoved: number;
  filesFailed: number;
}

export interface RevealedFieldDto {
  isText: boolean;
  value: string;
}

export interface ContactSummaryDto {
  contactUuidHex: string;
  displayName: string;
  sharedBlockCount: number;
}

export interface ExportedCardDto {
  path: string;
}

export interface ListContactsDto {
  contacts: ContactSummaryDto[];
  unreadableCount: number;
}

export type RecipientKind = 'owner' | 'contact' | 'unknown';

export interface RecipientDto {
  uuidHex: string;
  kind: RecipientKind;
  displayName: string | null;
}

export interface CreateVaultDto {
  mnemonic: string;
}

export interface CreateTargetProbeDto {
  exists: boolean;
  isEmpty: boolean;
}

export type FieldValueDto =
  | { kind: 'text'; text: string }
  | { kind: 'bytes'; base64: string };

export interface FieldInputDto {
  name: string;
  value: FieldValueDto;
}

export interface RecordInputDto {
  recordType: string;
  tags: string[];
  fields: FieldInputDto[];
}

export interface RecordRefDto {
  blockUuidHex: string;
  recordUuidHex: string;
}

export interface RevealedFieldWithNameDto {
  name: string;
  isText: boolean;
  value: string;
}

export interface RecordRevealDto {
  fields: RevealedFieldWithNameDto[];
}

// #374 Task 9: repair-preview / approved-widening DTOs. NOTE the hex fields
// here are NOT the plain 32-hex-char form the rest of this file uses (e.g.
// `BlockSummaryDto.blockUuidHex`) — they are the Rust bridge's own
// lowercase-hyphenated `format_uuid_hyphenated` output (36 chars),
// passed through verbatim end-to-end. `ApprovedWideningDto` must echo back
// exactly the strings a `RepairPreviewDto` produced — no reformatting —
// since the file-fingerprint bind proves the approval matches what the
// user was shown.

export interface AddedRecipientDto {
  uuidHex: string;
  displayName: string;
  cardFingerprintHex: string;
}

export interface WideningReportDto {
  blockUuidHex: string;
  blockName: string;
  fileFingerprintHex: string;
  /** The committed manifest entry fingerprint the preview diffed against —
   * echo back verbatim as `ApprovedWideningDto.committedFingerprintHex`
   * (#391: the third consent bind making approvals structurally
   * single-use). */
  committedFingerprintHex: string;
  added: AddedRecipientDto[];
}

export interface RepairPreviewDto {
  widenings: WideningReportDto[];
}

export interface ApprovedWideningDto {
  blockUuidHex: string;
  fileFingerprintHex: string;
  committedFingerprintHex: string;
  addedUuidsHex: string[];
}

export function isAppError(err: unknown): err is AppError {
  if (typeof err !== 'object' || err === null || !('code' in err)) {
    return false;
  }
  const code = (err as { code: unknown }).code;
  return typeof code === 'string' && KNOWN_ERROR_CODES.has(code as AppErrorCode);
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (err) {
    if (isAppError(err)) {
      throw err;
    }
    // Tauri can also reject with a bare string (panics, serialization
    // failures pre-AppError-mapping) or with a `{ code }` object whose
    // code is not in the known set (e.g. a future Rust variant). Log the
    // original — without this the developer-facing breadcrumb is lost —
    // then surface a typed `internal` so the UI still renders a coherent
    // toast.
    console.error(`IPC ${cmd} returned non-AppError rejection`, err);
    throw { code: 'internal' } satisfies AppError;
  }
}

export async function createVault(
  folderPath: string,
  displayName: string,
  password: string
): Promise<CreateVaultDto> {
  return call<CreateVaultDto>('create_vault', { folderPath, displayName, password });
}

export async function probeCreateTarget(folderPath: string): Promise<CreateTargetProbeDto> {
  return call<CreateTargetProbeDto>('probe_create_target', { folderPath });
}

export async function pickVaultFolder(): Promise<string | null> {
  return call<string | null>('pick_vault_folder', {});
}

export async function pickCreateFolder(): Promise<string | null> {
  return call<string | null>('pick_create_folder', {});
}

export async function pickContactCard(): Promise<string | null> {
  return call<string | null>('pick_contact_card', {});
}

export async function pickExportDir(): Promise<string | null> {
  return call<string | null>('pick_export_dir', {});
}

export async function unlockWithPassword(
  folderPath: string,
  password: string
): Promise<ManifestDto> {
  return call<ManifestDto>('unlock_with_password', { folderPath, password });
}

/**
 * Adopt crash residue in a vault whose most recent open failed with
 * `vault_needs_repair` (#374). Same shape as `unlockWithPassword` — on
 * success the returned `ManifestDto` populates the session exactly like a
 * normal unlock. Rejects with `repair_rejected` (carrying a human-readable
 * `detail`) when the residue isn't safely adoptable — see
 * `repair_vault.rs`'s equal-clock invariant.
 *
 * `approvals` (#374 Task 9) is the user's consented recipient-widening set,
 * built from a prior `previewRepair` result — pass `[]` to preserve the
 * pre-Task-9 fail-closed behavior (every widening rejected).
 */
export async function repairVault(
  folderPath: string,
  password: string,
  approvals: ApprovedWideningDto[]
): Promise<ManifestDto> {
  return call<ManifestDto>('repair_vault', { folderPath, password, approvals });
}

/**
 * Read-only preview of the recipient widenings a `repairVault` call would
 * need consent for (#374 Task 9) — invoked from the same locked "Repair
 * now?" affordance, before the user approves anything. Performs no vault
 * mutation and does not unlock the session.
 */
export async function previewRepair(
  folderPath: string,
  password: string
): Promise<RepairPreviewDto> {
  return call<RepairPreviewDto>('preview_repair', { folderPath, password });
}

export async function listBlocks(): Promise<BlockSummaryDto[]> {
  return call<BlockSummaryDto[]>('list_blocks');
}

export async function getManifest(): Promise<ManifestDto> {
  return call<ManifestDto>('get_manifest');
}

export async function readBlock(
  blockUuidHex: string,
  includeDeleted = false
): Promise<BlockDetailDto> {
  return call<BlockDetailDto>('read_block', { blockUuidHex, includeDeleted });
}

export async function revealField(
  blockUuidHex: string,
  recordUuidHex: string,
  fieldName: string
): Promise<RevealedFieldDto> {
  return call<RevealedFieldDto>('reveal_field', { blockUuidHex, recordUuidHex, fieldName });
}

export async function createBlock(blockName: string): Promise<BlockSummaryDto> {
  return call<BlockSummaryDto>('create_block', { blockName });
}

export async function renameBlock(blockUuidHex: string, newName: string): Promise<BlockSummaryDto> {
  return call<BlockSummaryDto>('rename_block', { blockUuidHex, newName });
}

export async function moveRecord(
  sourceBlockUuidHex: string,
  targetBlockUuidHex: string,
  sourceRecordUuidHex: string
): Promise<RecordRefDto> {
  return call<RecordRefDto>('move_record', { sourceBlockUuidHex, targetBlockUuidHex, sourceRecordUuidHex });
}

export async function saveRecord(blockUuidHex: string, record: RecordInputDto): Promise<RecordRefDto> {
  return call<RecordRefDto>('save_record', { blockUuidHex, record });
}

export async function saveRecordEdit(
  blockUuidHex: string,
  recordUuidHex: string,
  record: RecordInputDto
): Promise<RecordRefDto> {
  return call<RecordRefDto>('save_record_edit', { blockUuidHex, recordUuidHex, record });
}

export async function revealRecord(blockUuidHex: string, recordUuidHex: string): Promise<RecordRevealDto> {
  return call<RecordRevealDto>('reveal_record', { blockUuidHex, recordUuidHex });
}

export async function tombstoneRecord(
  blockUuidHex: string,
  recordUuidHex: string
): Promise<RecordRefDto> {
  return call<RecordRefDto>('tombstone_record', { blockUuidHex, recordUuidHex });
}

export async function resurrectRecord(
  blockUuidHex: string,
  recordUuidHex: string
): Promise<RecordRefDto> {
  return call<RecordRefDto>('resurrect_record', { blockUuidHex, recordUuidHex });
}

export async function trashBlock(blockUuidHex: string): Promise<void> {
  return call<void>('trash_block', { blockUuidHex });
}

export async function restoreBlock(blockUuidHex: string): Promise<BlockSummaryDto> {
  return call<BlockSummaryDto>('restore_block', { blockUuidHex });
}

export async function listTrashedBlocks(): Promise<TrashedBlockDto[]> {
  return call<TrashedBlockDto[]>('list_trashed_blocks', {});
}

export async function previewRetention(): Promise<RetentionPreviewDto> {
  return call<RetentionPreviewDto>('preview_retention', {});
}

export async function runRetention(): Promise<RetentionReportDto> {
  return call<RetentionReportDto>('run_retention', {});
}

export async function purgeBlock(blockUuidHex: string): Promise<PurgeReportDto> {
  return call<PurgeReportDto>('purge_block', { blockUuidHex });
}

export async function emptyTrash(): Promise<EmptyTrashReportDto> {
  return call<EmptyTrashReportDto>('empty_trash', {});
}

export async function getSettings(): Promise<SettingsDto> {
  return call<SettingsDto>('get_settings');
}

export async function setSettings(settings: SettingsDto): Promise<void> {
  return call<void>('set_settings', { settings });
}

/**
 * Verify the vault password for a write re-auth. Resolves on a correct
 * password; rejects with `wrong_password` on a bad one, `not_unlocked` if
 * the session has been locked meanwhile. Runs a full Argon2id on the backend
 * (~1-2s) — callers await it behind the grace window.
 */
export async function verifyPassword(password: string): Promise<void> {
  return call<void>('verify_password', { password });
}

export async function listContacts(): Promise<ListContactsDto> {
  return call<ListContactsDto>('list_contacts', {});
}

export async function listBlockRecipients(blockUuidHex: string): Promise<RecipientDto[]> {
  return call<RecipientDto[]>('block_recipients', { blockUuidHex });
}

export async function listContactBlocks(contactUuidHex: string): Promise<BlockSummaryDto[]> {
  return call<BlockSummaryDto[]>('list_contact_blocks', { contactUuidHex });
}

export async function importContact(cardPath: string): Promise<ContactSummaryDto> {
  return call<ContactSummaryDto>('import_contact', { cardPath });
}

export async function shareBlock(blockUuidHex: string, recipientUuidHex: string): Promise<void> {
  return call<void>('share_block', { blockUuidHex, recipientUuidHex });
}

export async function revokeBlockFrom(
  blockUuidHex: string,
  recipientUuidHex: string
): Promise<void> {
  return call<void>('revoke_block_from', { blockUuidHex, recipientUuidHex });
}

export async function exportContactCard(destDir: string): Promise<ExportedCardDto> {
  return call<ExportedCardDto>('export_contact_card', { destDir });
}

export async function deleteContactCard(contactUuidHex: string): Promise<void> {
  return call<void>('delete_contact_card', { contactUuidHex });
}

export async function lock(): Promise<void> {
  return call<void>('lock');
}

export async function notifyActivity(): Promise<void> {
  return call<void>('notify_activity');
}

export async function syncStatus(): Promise<SyncStatusDto> {
  return call<SyncStatusDto>('sync_status');
}

export async function syncNow(password: string): Promise<SyncOutcome> {
  return call<SyncOutcome>('sync_now', { password });
}

export async function syncCommitDecisions(
  password: string,
  decisions: VetoDecisionDto[],
  manifestHash: number[]
): Promise<SyncOutcome> {
  return call<SyncOutcome>('sync_commit_decisions', { password, decisions, manifestHash });
}
