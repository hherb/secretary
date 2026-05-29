// Pure wizard step state + helpers for the create-vault flow. No IPC, no DOM.
// The host component (CreateVault.svelte) owns the IPC calls and holds the
// step as Svelte $state; this module is the testable logic core.

export type WizardStep =
  | { step: 'folder' }
  | { step: 'credentials'; folder: string }
  | { step: 'mnemonic'; folder: string; mnemonic: string };

export function startWizard(): WizardStep {
  return { step: 'folder' };
}

export function toCredentials(folder: string): WizardStep {
  return { step: 'credentials', folder };
}

export function toMnemonic(folder: string, mnemonic: string): WizardStep {
  return { step: 'mnemonic', folder, mnemonic };
}

/** True iff both password fields are non-empty and identical. */
export function passwordsMatch(pw: string, confirm: string): boolean {
  return pw.length > 0 && pw === confirm;
}

/** Join a picked parent folder and a subfolder name into a target path.
 *  Returns null for an empty name, one containing a path separator, or a
 *  traversal segment (`.` / `..`) — we create exactly one new level inside
 *  the parent, never a nested path and never the parent (or above) itself.
 *  The backend re-checks emptiness authoritatively, so this is a UX guard
 *  (keep the "Will create:" hint truthful), not the security boundary. */
export function joinSubfolder(parent: string, name: string): string | null {
  const trimmed = name.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.includes('/') || trimmed.includes('\\')) return null;
  if (trimmed === '.' || trimmed === '..') return null;
  const sep = parent.includes('\\') ? '\\' : '/';
  const base = parent.endsWith(sep) ? parent.slice(0, -sep.length) : parent;
  return `${base}${sep}${trimmed}`;
}

export interface MnemonicWord {
  index: number;
  word: string;
}

/** Split a recovery phrase into numbered words for the display grid. */
export function groupMnemonicWords(phrase: string): MnemonicWord[] {
  return phrase
    .split(/\s+/)
    .filter((w) => w.length > 0)
    .map((word, i) => ({ index: i + 1, word }));
}
