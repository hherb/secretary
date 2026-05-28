<script lang="ts">
  import { sessionState } from '../lib/stores';
  import { userMessageForWarning } from '../lib/errors';
  import BlockCard from '../components/BlockCard.svelte';
  import TopBar from '../components/TopBar.svelte';
  import SettingsDialog from '../components/SettingsDialog.svelte';

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

    <div class="vault__block-count">
      {manifest.blockCount} block{manifest.blockCount === 1 ? '' : 's'}
    </div>

    <div class="vault__block-list">
      {#each manifest.blockSummaries as block (block.blockUuidHex)}
        <BlockCard {block} />
      {/each}
    </div>

    <SettingsDialog
      bind:open={settingsOpen}
      onClose={() => (settingsOpen = false)}
    />
  </div>
{/if}
