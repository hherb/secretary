// Typed wrappers for the desktop presence (macOS Touch ID) commands (#277).
// Mirrors ipc.ts conventions. `authenticate_presence` returns a tagged outcome
// ({ kind: 'authenticated' | ... }); we surface the bare tag to callers.
//
// `writePresencePref` is deliberately NOT here: it's a `write`-classified
// command in writeCommands.ts, and the write-gate-coverage test (#280) layer 2
// check only scans ipc.ts's raw source for a wrapper's `call<...>('cmd', …)`
// binding. Its wrapper lives in ipc.ts alongside every other write command so
// that scan keeps covering it.

import { invoke } from '@tauri-apps/api/core';

export type PresenceOutcome = 'authenticated' | 'fallback' | 'unavailable' | 'cancelled';
export type PresenceAvailability = 'available' | 'notEnrolled' | 'notAvailable' | 'unsupported';

export interface PresencePrefDto {
  biometricEnabled: boolean;
  availability: PresenceAvailability;
}

interface PresenceOutcomeDto {
  kind: PresenceOutcome;
}

/** Fire the native Touch ID sheet. Never rejects for a normal outcome —
 *  cancel/fallback/unavailable are returned as tags. On an unexpected IPC
 *  fault, fail safe to 'unavailable' so the caller routes to the password. */
export async function authenticatePresence(reason: string): Promise<PresenceOutcome> {
  try {
    const dto = await invoke<PresenceOutcomeDto>('authenticate_presence', { reason });
    return dto.kind;
  } catch (err) {
    console.error('authenticate_presence failed; falling back to password', err);
    return 'unavailable';
  }
}

export async function readPresencePref(): Promise<PresencePrefDto> {
  return invoke<PresencePrefDto>('read_presence_pref');
}
