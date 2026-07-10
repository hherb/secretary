<script lang="ts">
  // A single trashed block within TrashView. Models BlockCard's leaf-row
  // shape but is non-navigable (trashed blocks have no browse target) and
  // carries a Restore action via a callback prop.

  import type { TrashedBlockDto } from '../../lib/ipc';
  import { formatTrashedWhen } from '../../lib/trash';

  type Props = {
    entry: TrashedBlockDto;
    onRestore: (entry: TrashedBlockDto) => void;
    onPurge: (entry: TrashedBlockDto) => void;
  };
  let { entry, onRestore, onPurge }: Props = $props();
</script>

<div class="trashed-row">
  <div class="trashed-row__name">{entry.blockName}</div>
  <div class="trashed-row__when">trashed {formatTrashedWhen(entry.tombstonedAtMs)}</div>
  <button
    type="button"
    class="trashed-row__restore"
    aria-label={`Restore block ${entry.blockName}`}
    onclick={() => onRestore(entry)}
  >
    Restore
  </button>
  <button
    type="button"
    class="trashed-row__purge"
    aria-label={`Permanently delete block ${entry.blockName}`}
    onclick={() => onPurge(entry)}
  >
    Delete forever
  </button>
</div>
