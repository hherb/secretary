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

export async function unlockWithPassword(
  folderPath: string,
  password: string
): Promise<ManifestDto> {
  return call<ManifestDto>('unlock_with_password', { folderPath, password });
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

export async function getSettings(): Promise<SettingsDto> {
  return call<SettingsDto>('get_settings');
}

export async function setSettings(settings: SettingsDto): Promise<void> {
  return call<void>('set_settings', { settings });
}

export async function listContacts(): Promise<ListContactsDto> {
  return call<ListContactsDto>('list_contacts', {});
}

export async function listBlockRecipients(blockUuidHex: string): Promise<RecipientDto[]> {
  return call<RecipientDto[]>('block_recipients', { blockUuidHex });
}

export async function importContact(cardPath: string): Promise<ContactSummaryDto> {
  return call<ContactSummaryDto>('import_contact', { cardPath });
}

export async function shareBlock(blockUuidHex: string, recipientUuidHex: string): Promise<void> {
  return call<void>('share_block', { blockUuidHex, recipientUuidHex });
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
