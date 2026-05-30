<script lang="ts">
  import { sessionState, refreshManifest } from '../lib/stores';
  import { userMessageForWarning } from '../lib/errors';
  import BlockCard from '../components/BlockCard.svelte';
  import TopBar from '../components/TopBar.svelte';
  import SettingsDialog from '../components/SettingsDialog.svelte';
  import { browseNav, openBlock, openNewBlock, back } from '../lib/browse';
  import RecordList from '../components/RecordList.svelte';
  import FieldViewer from '../components/FieldViewer.svelte';
  import NewBlock from '../components/edit/NewBlock.svelte';
  import RecordEditor from '../components/edit/RecordEditor.svelte';

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
      <div class="vault__block-count">
        {manifest.blockCount} block{manifest.blockCount === 1 ? '' : 's'}
      </div>
      <div class="vault__block-list">
        {#each manifest.blockSummaries as block (block.blockUuidHex)}
          <BlockCard {block} onClick={openBlock} />
        {/each}
      </div>
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
  </div>
{/if}
