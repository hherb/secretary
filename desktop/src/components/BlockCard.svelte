<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  // Locale-aware short date (year + abbreviated month + day). Browser's
  // Intl.DateTimeFormat is bundled — no external dep. Format varies by
  // locale ("Jun 15, 2024" vs "15 Jun 2024"); tests pin year-substring
  // presence rather than exact format.
  function formatShortDate(ms: number): string {
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    }).format(new Date(ms));
  }
</script>

<button
  type="button"
  class="block-card"
  disabled
  title="Block details land in the next release"
  aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
>
  <div class="block-card__name">{block.blockName}</div>
  <div class="block-card__meta">modified {formatShortDate(block.lastModifiedMs)}</div>
</button>
