<script lang="ts">
  import { sessionState } from '../lib/stores';
  import { userMessageForWarning } from '../lib/errors';
  import BlockCard from '../components/BlockCard.svelte';
  import TopBar from '../components/TopBar.svelte';

  // First N hex chars of the vault UUID are visible in the TopBar; the
  // rest is collapsed to an ellipsis. 8 is enough to disambiguate
  // multiple vaults visually without dominating the bar.
  const UUID_LABEL_PREFIX_LEN = 8;

  // Defensive narrowing — Vault is only routed when status === 'unlocked'
  // by App.svelte, but reading state here keeps Vault decoupled from the
  // router's invariant. If invoked from any other state, render nothing.
  let unlocked = $derived(
    $sessionState.status === 'unlocked' ? $sessionState : null
  );
</script>

{#if unlocked}
  {@const manifest = unlocked.manifest}
  {@const vaultLabel = manifest.vaultUuidHex.slice(0, UUID_LABEL_PREFIX_LEN) + '…'}

  <div class="vault">
    <TopBar {vaultLabel} />

    {#each manifest.warnings as warning}
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
  </div>
{/if}
