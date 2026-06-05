// Pure confirm-dialog copy for the D.1.11 revoke action. No IPC / DOM — the IPC
// wrapper lives in ipc.ts. Single source of the forward-secrecy caveat wording,
// shared by both revoke surfaces (BlockRecipients banner, ContactRow reverse map).

export type RevokeConfirmCopy = { title: string; body: string; confirmLabel: string };

/**
 * Build the confirm-dialog copy for revoking a recipient's access to a block.
 * The block name and recipient label are interpolated into the title; the body
 * states the forward-secrecy boundary explicitly: a revoke re-keys the block so
 * the former recipient cannot open future versions, but they keep any copy they
 * have already seen. Pure.
 */
export function revokeConfirmCopy(blockName: string, recipientLabel: string): RevokeConfirmCopy {
  return {
    title: `Stop sharing “${blockName}” with ${recipientLabel}?`,
    body:
      `${recipientLabel} won’t be able to open this block after you revoke — it is ` +
      `re-encrypted so future changes stay private. They keep any copy they have ` +
      `already seen; revoking can’t reach data they already opened.`,
    confirmLabel: 'Revoke'
  };
}
