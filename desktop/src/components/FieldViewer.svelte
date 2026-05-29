<script lang="ts">
  import type { BlockSummaryDto, RecordDto } from '../lib/ipc';
  type Props = { block: BlockSummaryDto; record: RecordDto };
  let { block: _block, record: _record }: Props = $props();
</script>

<div class="field-viewer"><!-- fleshed out in Task 5 --></div>
