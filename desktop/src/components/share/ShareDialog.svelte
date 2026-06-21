<script lang="ts">
  // Block-sharing modal (D.1.6, spec §7). On mount it lists the vault's
  // imported contacts (the owner is excluded backend-side by list_contacts),
  // lets the user pick one, and shares the given block with that recipient.
  // It also offers an inline "import a contact card" affordance so a user
  // with no contacts yet can add one without leaving the dialog.
  //
  // Native <dialog> mirroring ConfirmDialog: showModal() on mount via $effect,
  // Esc handled by preventing the native close so the parent's unmount (driven
  // by onClose) is the single teardown path.
  //
  // Secret hygiene: only contact display names + UUID hex strings ever reach
  // the DOM — never the contact-card bytes. importContact takes a filesystem
  // path; the card is parsed in the Rust core and only a ContactSummaryDto
  // (uuid + display name) crosses the IPC boundary back here.

  import type { BlockSummaryDto } from '../../lib/ipc';
  import { listContacts, importContact, shareBlock, isAppError } from '../../lib/ipc';
  import type { ContactSummaryDto } from '../../lib/ipc';
  import { sortContacts } from '../../lib/contacts';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import PathPicker from '../PathPicker.svelte';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';

  type Props = {
    block: BlockSummaryDto;
    onClose: () => void;
  };
  let { block, onClose }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();

  let contacts = $state<ContactSummaryDto[]>([]);
  let unreadable = $state(0);
  let selected = $state<string | null>(null);
  let busy = $state(false);
  let error = $state<AppError | null>(null);

  // Monotonic token guarding against a stale refresh overwriting a newer one
  // (e.g. an import resolves after a later import started). Only the latest
  // load is allowed to commit its result to component state.
  let loadToken = 0;

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  // Initial population. Runs once on mount; subsequent refreshes go through
  // refresh() after an import.
  $effect(() => {
    void refresh();
  });

  async function refresh(): Promise<void> {
    const token = ++loadToken;
    try {
      const dto = await listContacts();
      if (token !== loadToken) return;
      contacts = sortContacts(dto.contacts);
      unreadable = dto.unreadableCount;
    } catch (err) {
      if (token !== loadToken) return;
      error = isAppError(err) ? err : { code: 'internal' };
    }
  }

  async function onImport(path: string): Promise<void> {
    if (busy) return;
    busy = true;
    error = null;
    try {
      await importContact(path);
      await refresh();
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }

  function select(uuidHex: string): void {
    selected = uuidHex;
  }

  async function confirmShare(): Promise<void> {
    if (!selected || busy) return;
    error = null;
    try {
      await authorizeWrite('Confirm sharing this block');
    } catch (err) {
      if (err === ReauthCancelled) return; // dialog stays open
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    busy = true;
    try {
      await shareBlock(block.blockUuidHex, selected);
      onClose();
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }

  // Esc dismiss: prevent the native close so the parent's unmount (in
  // response to onClose) is the single teardown path — matches ConfirmDialog.
  function onNativeCancel(event: Event) {
    event.preventDefault();
    onClose();
  }
</script>

<dialog bind:this={dialogEl} class="share-dialog" oncancel={onNativeCancel}>
  <h2 class="share-dialog__title">Share “{block.blockName}”</h2>

  {#if unreadable > 0}
    <p class="share-dialog__warn" role="status">
      {unreadable} contact{unreadable === 1 ? '' : 's'} unreadable and hidden.
    </p>
  {/if}

  {#if contacts.length === 0}
    <p class="share-dialog__empty">No contacts yet.</p>
  {:else}
    <ul class="contact-list">
      {#each contacts as contact (contact.contactUuidHex)}
        <li>
          <button
            type="button"
            class="contact-row"
            class:contact-row--selected={selected === contact.contactUuidHex}
            aria-pressed={selected === contact.contactUuidHex}
            onclick={() => select(contact.contactUuidHex)}
          >
            {contact.displayName}
          </button>
        </li>
      {/each}
    </ul>
  {/if}

  <div class="share-dialog__import">
    <PathPicker
      value=""
      onSelect={onImport}
      disabled={busy}
      directory={false}
      filters={[{ name: 'Contact card', extensions: ['card'] }]}
      title="Import a contact card"
      label="Import a contact…"
    />
  </div>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="share-dialog__error" role="alert">
      {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
    </p>
  {/if}

  <div class="share-dialog__actions">
    <button type="button" class="share-dialog__button" onclick={onClose}>
      Cancel
    </button>
    <button
      type="button"
      class="share-dialog__button share-dialog__button--primary"
      disabled={!selected || busy}
      onclick={confirmShare}
    >
      Share
    </button>
  </div>
</dialog>
