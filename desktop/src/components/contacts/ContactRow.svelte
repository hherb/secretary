<script lang="ts">
  // One imported contact: display name + how many of the owner's blocks it
  // receives + a Delete action. D.1.9 adds an inline, lazily-fetched reverse
  // map: click the row to expand the list of blocks this contact receives;
  // click a block to open it. Mirrors BlockRecipients' load/error/empty shape,
  // but fetches on first expand (not on mount) and caches the result.
  // Caches the fetched list for the component's lifetime; assumes one instance
  // per contactUuidHex — ContactsPane's keyed {#each} is the invalidation
  // mechanism (a new uuid remounts the row).
  import {
    listContactBlocks,
    revokeBlockFrom,
    isAppError,
    type BlockSummaryDto,
    type ContactSummaryDto
  } from '../../lib/ipc';
  import { sortBlocks } from '../../lib/blocks';
  import { openBlock } from '../../lib/browse';
  import { revokeConfirmCopy } from '../../lib/revoke';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import ConfirmDialog from '../delete/ConfirmDialog.svelte';

  type Props = {
    contact: ContactSummaryDto;
    onDelete: (c: ContactSummaryDto) => void;
    onRevoked: () => void;
  };
  let { contact, onDelete, onRevoked }: Props = $props();

  const blocksLabel = $derived(
    contact.sharedBlockCount === 1
      ? 'receives 1 block'
      : `receives ${contact.sharedBlockCount} blocks`
  );

  let expanded = $state(false);
  let blocks = $state<BlockSummaryDto[] | null>(null);
  let loading = $state(false);
  let error = $state<AppError | null>(null);
  let fetched = false; // lazy-fetch-once guard

  async function ensureLoaded() {
    if (fetched) return;
    fetched = true;
    loading = true;
    error = null;
    try {
      const rows = await listContactBlocks(contact.contactUuidHex);
      blocks = sortBlocks(rows);
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
      fetched = false; // allow a retry on the next expand after an error
    } finally {
      loading = false;
    }
  }

  function toggle() {
    expanded = !expanded;
    if (expanded) void ensureLoaded();
  }

  let pendingRevoke = $state<BlockSummaryDto | null>(null);

  async function confirmRevoke() {
    const target = pendingRevoke;
    pendingRevoke = null;
    if (!target) return;
    error = null;
    try {
      await revokeBlockFrom(target.blockUuidHex, contact.contactUuidHex);
      fetched = false; // drop the lazy-fetch cache so the list re-loads fresh
      await ensureLoaded();
      onRevoked(); // parent re-runs listContacts → sharedBlockCount badge drops
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<div class="contact-card">
  <div class="contact-card-row">
    <button
      type="button"
      class="contact-card-row__toggle"
      aria-expanded={expanded}
      aria-controls={`contact-blocks-${contact.contactUuidHex}`}
      onclick={toggle}
    >
      <span class="contact-card-row__name">{contact.displayName}</span>
      <span class="contact-card-row__count">{blocksLabel}</span>
      <span class="contact-card-row__chevron" aria-hidden="true">{expanded ? '▴' : '▾'}</span>
    </button>
    <button type="button" class="contact-card-row__delete" onclick={() => onDelete(contact)}>
      Delete
    </button>
  </div>

  {#if expanded}
    <div id={`contact-blocks-${contact.contactUuidHex}`}>
      {#if error}
        {@const msg = userMessageFor(error)}
        <p class="contact-blocks__error" role="alert">
          {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
        </p>
      {:else if loading || blocks === null}
        <p class="contact-blocks__loading">Loading blocks…</p>
      {:else if blocks.length === 0}
        <p class="contact-blocks__empty">No shared blocks.</p>
      {:else}
        <ul class="contact-blocks__list">
          {#each blocks as b (b.blockUuidHex)}
            <li class="contact-blocks__row">
              <button type="button" class="contact-blocks__item" onclick={() => openBlock(b)}>
                {b.blockName}
              </button>
              <button
                type="button"
                class="contact-blocks__revoke"
                aria-label={`Stop sharing “${b.blockName}” with ${contact.displayName}`}
                onclick={() => (pendingRevoke = b)}
              >
                ✕
              </button>
            </li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}

  {#if pendingRevoke}
    {@const copy = revokeConfirmCopy(pendingRevoke.blockName, contact.displayName)}
    <ConfirmDialog
      title={copy.title}
      body={copy.body}
      confirmLabel={copy.confirmLabel}
      onConfirm={confirmRevoke}
      onCancel={() => (pendingRevoke = null)}
    />
  {/if}
</div>
