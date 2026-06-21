<script lang="ts">
  // Contacts pane (spec D.1.7) — reached from the Vault "Contacts" entry.
  // Mirrors TrashView's load/error/empty + loadSeq generation guard. Hosts
  // "Export my card" (PathPicker folder mode → exportContactCard) and the
  // contact list with per-contact delete (warn-but-allow via ConfirmDialog).
  import {
    listContacts,
    deleteContactCard,
    exportContactCard,
    isAppError,
    type ContactSummaryDto
  } from '../../lib/ipc';
  import { sortContacts } from '../../lib/contacts';
  import { back } from '../../lib/browse';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import PathPicker from '../PathPicker.svelte';
  import ConfirmDialog from '../delete/ConfirmDialog.svelte';
  import ContactRow from './ContactRow.svelte';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';

  let contacts = $state<ContactSummaryDto[] | null>(null);
  let unreadable = $state(0);
  let error = $state<AppError | null>(null);
  let notice = $state<string | null>(null);
  let pendingDelete = $state<ContactSummaryDto | null>(null);

  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    error = null;
    try {
      const res = await listContacts();
      if (seq === loadSeq) {
        contacts = sortContacts(res.contacts);
        unreadable = res.unreadableCount;
      }
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }
  $effect(() => {
    void load();
  });

  async function onExportSelect(destDir: string) {
    error = null;
    notice = null;
    try {
      const dto = await exportContactCard(destDir);
      notice = `Card exported to ${dto.path}`;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  function requestDelete(c: ContactSummaryDto) {
    pendingDelete = c;
  }

  async function confirmDelete() {
    const target = pendingDelete;
    if (!target) return;
    error = null;
    notice = null;
    try {
      await authorizeWrite('Confirm deleting this contact');
    } catch (err) {
      if (err === ReauthCancelled) return; // ConfirmDialog stays open (pendingDelete still set)
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    pendingDelete = null; // now AFTER the gate; dialog closes only on success
    try {
      await deleteContactCard(target.contactUuidHex);
      await load();
    } catch (e) {
      // A not-found means the on-disk contacts/ already diverged from the
      // list we rendered (the card was deleted out-of-band, or this list is
      // stale). The user's intent — remove the row — is already satisfied,
      // so treat it as benign: re-sync the list and note it, rather than
      // surface an error and leave the dead row lingering. (`load()` clears
      // `error`; set the notice after it so the message survives.)
      if (isAppError(e) && e.code === 'contact_not_found') {
        await load();
        notice = `${target.displayName} was already removed.`;
        return;
      }
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  const confirmBody = $derived(
    pendingDelete && pendingDelete.sharedBlockCount > 0
      ? `${pendingDelete.displayName} receives ${pendingDelete.sharedBlockCount} of your blocks. ` +
          "Deleting their card won't revoke access they already have, but you won't be able to " +
          're-share those blocks to anyone.'
      : `Remove ${pendingDelete?.displayName ?? 'this contact'} from your vault?`
  );
</script>

<section class="contacts-pane">
  <button type="button" class="contacts-pane__back" onclick={() => back()}>← Contacts</button>

  <div class="contacts-pane__export">
    <span class="contacts-pane__export-label">Export my card</span>
    <PathPicker
      value=""
      directory={true}
      title="Choose a folder to export your card to"
      label="Export…"
      onSelect={onExportSelect}
    />
  </div>

  {#if notice}
    <p class="contacts-pane__notice" role="status">{notice}</p>
  {/if}
  {#if unreadable > 0}
    <p class="contacts-pane__warn" role="alert">
      {unreadable} contact file(s) could not be read.
    </p>
  {/if}

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="contacts-pane__error" role="alert">
      {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
    </p>
  {:else if contacts === null}
    <p class="contacts-pane__loading">Loading…</p>
  {:else if contacts.length === 0}
    <p class="contacts-pane__empty">No contacts imported yet.</p>
  {:else}
    {#each contacts as contact (contact.contactUuidHex)}
      <ContactRow {contact} onDelete={requestDelete} onRevoked={load} />
    {/each}
  {/if}

  {#if pendingDelete}
    <ConfirmDialog
      title="Delete this contact?"
      body={confirmBody}
      confirmLabel={pendingDelete.sharedBlockCount > 0 ? 'Delete anyway' : 'Delete'}
      onConfirm={confirmDelete}
      onCancel={() => (pendingDelete = null)}
    />
  {/if}
</section>
