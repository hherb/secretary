<script lang="ts">
  import { sessionState, refreshManifest } from '../lib/stores';
  import { userMessageForWarning, userMessageFor, type AppError } from '../lib/errors';
  import { trashBlock, isAppError, type BlockSummaryDto } from '../lib/ipc';
  import BlockCard from '../components/BlockCard.svelte';
  import TopBar from '../components/TopBar.svelte';
  import SettingsDialog from '../components/SettingsDialog.svelte';
  import { browseNav, openBlock, openNewBlock, openTrash, openContacts, back } from '../lib/browse';
  import RecordList from '../components/RecordList.svelte';
  import FieldViewer from '../components/FieldViewer.svelte';
  import NewBlock from '../components/edit/NewBlock.svelte';
  import RecordEditor from '../components/edit/RecordEditor.svelte';
  import TrashView from '../components/delete/TrashView.svelte';
  import ContactsPane from '../components/contacts/ContactsPane.svelte';
  import ConfirmDialog from '../components/delete/ConfirmDialog.svelte';
  import ShareDialog from '../components/share/ShareDialog.svelte';

  // First N hex chars of the vault UUID are visible in the TopBar; the
  // rest is collapsed to an ellipsis. 8 is enough to disambiguate
  // multiple vaults visually without dominating the bar.
  const UUID_LABEL_PREFIX_LEN = 8;

  // Backend currently emits 32-hex-char vault UUIDs so the slice always
  // returns a strict prefix; the guard defends against future shorter
  // identifiers (e.g. a debug build, or a v2 schema change) so we never
  // render a misleading "abc…" tail on a value that's already complete.
  function labelForUuid(hex: string): string {
    return hex.length <= UUID_LABEL_PREFIX_LEN
      ? hex
      : hex.slice(0, UUID_LABEL_PREFIX_LEN) + '…';
  }

  // Defensive narrowing — Vault is only routed when status === 'unlocked'
  // by App.svelte, but reading state here keeps Vault decoupled from the
  // router's invariant. If invoked from any other state, render nothing.
  let unlocked = $derived(
    $sessionState.status === 'unlocked' ? $sessionState : null
  );

  let settingsOpen = $state(false);
  // Block awaiting trash confirmation; ConfirmDialog mounts while set.
  let pendingTrash = $state<BlockSummaryDto | null>(null);
  // Block awaiting a share; ShareDialog mounts while set.
  let blockToShare = $state<BlockSummaryDto | null>(null);
  // Trash flow is initiated here (not in a child editor) so its typed
  // error surfaces inline on the blocks pane, mirroring how NewBlock /
  // RecordList render their own `role="alert"` rather than a global toast.
  let trashError = $state<AppError | null>(null);

  async function confirmTrash() {
    const target = pendingTrash;
    if (!target) return;
    pendingTrash = null;
    trashError = null;
    try {
      await trashBlock(target.blockUuidHex);
      await refreshManifest();
    } catch (err) {
      trashError = isAppError(err) ? err : { code: 'internal' };
    }
  }
</script>

{#if unlocked}
  {@const manifest = unlocked.manifest}
  {@const vaultLabel = labelForUuid(manifest.vaultUuidHex)}

  <div class="vault">
    <TopBar {vaultLabel} onOpenSettings={() => (settingsOpen = true)} />

    {#each manifest.warnings as warning, i (warning.code + '-' + i)}
      {@const msg = userMessageForWarning(warning)}
      <div class="vault__warning" role="status">
        <strong>{msg.title}</strong>
        {#if msg.detail}
          <span class="vault__warning-detail">{msg.detail}</span>
        {/if}
      </div>
    {/each}

    {#if $browseNav.level === 'blocks'}
      <button type="button" class="vault__new-block" onclick={() => openNewBlock()}>+ New block</button>
      <button type="button" class="vault__trash-entry" onclick={() => openTrash()}>🗑 Trash</button>
      <button type="button" class="vault__contacts-entry" onclick={() => openContacts()}>👤 Contacts</button>
      {#if trashError}
        {@const msg = userMessageFor(trashError)}
        <p class="vault__trash-error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
      {/if}
      <div class="vault__block-count">
        {manifest.blockCount} block{manifest.blockCount === 1 ? '' : 's'}
      </div>
      <div class="vault__block-list">
        {#each manifest.blockSummaries as block (block.blockUuidHex)}
          <BlockCard
            {block}
            onClick={openBlock}
            onTrash={(b) => (pendingTrash = b)}
            onShare={(b) => (blockToShare = b)}
          />
        {/each}
      </div>
    {:else if $browseNav.level === 'trash'}
      <TrashView />
    {:else if $browseNav.level === 'contacts'}
      <ContactsPane />
    {:else if $browseNav.level === 'records'}
      <RecordList block={$browseNav.block} />
    {:else if $browseNav.level === 'fields'}
      <FieldViewer block={$browseNav.block} record={$browseNav.record} />
    {:else if $browseNav.level === 'newBlock'}
      <NewBlock
        onCreated={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
    {:else if $browseNav.level === 'newRecord'}
      <RecordEditor
        block={$browseNav.block}
        record={null}
        onSaved={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
    {:else}
      <RecordEditor
        block={$browseNav.block}
        record={$browseNav.record}
        onSaved={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
    {/if}

    <SettingsDialog
      bind:open={settingsOpen}
      onClose={() => (settingsOpen = false)}
    />

    {#if pendingTrash}
      <ConfirmDialog
        title="Move this block to Trash?"
        body="It moves to Trash and can be restored from there."
        confirmLabel="Trash"
        onConfirm={confirmTrash}
        onCancel={() => (pendingTrash = null)}
      />
    {/if}

    {#if blockToShare}
      <ShareDialog
        block={blockToShare}
        onClose={() => { blockToShare = null; refreshManifest(); }}
      />
    {/if}
  </div>
{/if}
