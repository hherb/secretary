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

export async function getSettings(): Promise<SettingsDto> {
  return call<SettingsDto>('get_settings');
}

export async function setSettings(settings: SettingsDto): Promise<void> {
  return call<void>('set_settings', { settings });
}

export async function lock(): Promise<void> {
  return call<void>('lock');
}

export async function notifyActivity(): Promise<void> {
  return call<void>('notify_activity');
}
