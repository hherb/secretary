<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';

  type Props = { block: BlockSummaryDto; onClick: (block: BlockSummaryDto) => void };
  let { block, onClick }: Props = $props();
</script>

<button
  type="button"
  class="block-card"
  aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
  onclick={() => onClick(block)}
>
  <div class="block-card__name">{block.blockName}</div>
  <div class="block-card__meta">modified {formatShortDate(block.lastModifiedMs)}</div>
</button>
