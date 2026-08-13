<script lang="ts">
  import { sessionState, refreshManifest } from '../lib/stores';
  import { userMessageForWarning, userMessageFor, type AppError } from '../lib/errors';
  import { trashBlock, isAppError, type BlockSummaryDto } from '../lib/ipc';
  import { authorizeWrite, ReauthCancelled } from '../lib/writeGuard';
  import TopBar from '../components/TopBar.svelte';
  import SettingsDialog from '../components/SettingsDialog.svelte';
  import { get } from 'svelte/store';
  import { browseNav, openBlock, openNewBlock, openRenameBlock, openTrash, openContacts, back, shouldPopOnEscape } from '../lib/browse';
  import RecordList from '../components/RecordList.svelte';
  import FieldViewer from '../components/FieldViewer.svelte';
  import BlockNameDialog from '../components/edit/BlockNameDialog.svelte';
  import RecordEditor from '../components/edit/RecordEditor.svelte';
  import TrashView from '../components/delete/TrashView.svelte';
  import ContactsPane from '../components/contacts/ContactsPane.svelte';
  import ConfirmDialog from '../components/delete/ConfirmDialog.svelte';
  import ShareDialog from '../components/share/ShareDialog.svelte';
  import ReauthPasswordDialog from '../components/ReauthPasswordDialog.svelte';
  import { panesFor } from '../lib/panes';
  import PaneShell from '../components/PaneShell.svelte';
  import BlockSidebar from '../components/BlockSidebar.svelte';

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

  // #526 — the three panes are a pure projection of browseNav, never new
  // state. See lib/panes.ts for why.
  let panes = $derived(panesFor($browseNav));

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
    trashError = null;
    try {
      await authorizeWrite('Confirm trashing this block');
    } catch (err) {
      if (err === ReauthCancelled) return; // ConfirmDialog stays open (pendingTrash still set)
      trashError = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    pendingTrash = null; // now AFTER the gate; dialog closes only on success or non-cancel error
    try {
      await trashBlock(target.blockUuidHex);
      await refreshManifest();
    } catch (err) {
      trashError = isAppError(err) ? err : { code: 'internal' };
    }
  }

  // #164 - Esc pops one browse level. Window-level so it works regardless of
  // focus; the pure guard decides. Vault mounts only when unlocked, so the
  // Unlock screen is excluded structurally. Native <dialog>s own their own
  // Esc, so we no-op when one is open; likewise when a form control has focus.
  function handleKeydown(e: KeyboardEvent): void {
    if (e.key !== 'Escape') return;
    const dialogOpen = document.querySelector('dialog[open]') !== null;
    const el = document.activeElement;
    const inFormControl =
      el instanceof HTMLInputElement ||
      el instanceof HTMLTextAreaElement ||
      el instanceof HTMLSelectElement;
    if (shouldPopOnEscape(get(browseNav).level, dialogOpen, inFormControl)) {
      e.preventDefault();
      back();
    }
  }

  $effect(() => {
    window.addEventListener('keydown', handleKeydown);
    return () => window.removeEventListener('keydown', handleKeydown);
  });
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

    <PaneShell spanDetail={panes.detail.kind === 'spanned'}>
      {#snippet sidebar()}
        <BlockSidebar
          blocks={manifest.blockSummaries}
          blockCount={manifest.blockCount}
          selection={panes.sidebar}
          frozen={panes.list.kind === 'records' && panes.list.frozen}
          onOpenBlock={openBlock}
          onNewBlock={openNewBlock}
          onOpenTrash={openTrash}
          onOpenContacts={openContacts}
          onTrashBlock={(b) => (pendingTrash = b)}
          onShareBlock={(b) => (blockToShare = b)}
          onRenameBlock={openRenameBlock}
        />
        {#if trashError}
          {@const msg = userMessageFor(trashError)}
          <p class="vault__trash-error" role="alert">
            {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
          </p>
        {/if}
      {/snippet}

      {#snippet list()}
        {#if panes.list.kind === 'prompt'}
          <p class="vault__pane-prompt">{panes.list.message}</p>
        {:else if panes.list.kind === 'records'}
          <RecordList
            block={panes.list.block}
            blockCount={manifest.blockCount}
            selectedRecordUuidHex={panes.list.selectedRecordUuidHex}
            frozen={panes.list.frozen}
          />
        {:else if panes.list.kind === 'trash'}
          <TrashView />
        {:else if panes.list.kind === 'contacts'}
          <ContactsPane />
        {/if}
      {/snippet}

      {#snippet detail()}
        {#if panes.detail.kind === 'prompt'}
          <p class="vault__pane-prompt">{panes.detail.message}</p>
        {:else if panes.detail.kind === 'viewer'}
          {#key panes.detail.record.recordUuidHex}
            <FieldViewer block={panes.detail.block} record={panes.detail.record} />
          {/key}
        {:else if panes.detail.kind === 'editor'}
          {#key panes.detail.record?.recordUuidHex ?? 'new-record'}
            <RecordEditor
              block={panes.detail.block}
              record={panes.detail.record}
              onSaved={async () => { try { await refreshManifest(); } finally { back(); } }}
              onCancel={() => back()}
            />
          {/key}
        {/if}
      {/snippet}
    </PaneShell>

    {#if panes.modal.kind === 'blockName'}
      <BlockNameDialog
        mode={panes.modal.mode}
        onDone={async () => { try { await refreshManifest(); } finally { back(); } }}
        onCancel={() => back()}
      />
    {/if}

    <SettingsDialog
      bind:open={settingsOpen}
      onClose={() => (settingsOpen = false)}
    />

    <ReauthPasswordDialog />

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
