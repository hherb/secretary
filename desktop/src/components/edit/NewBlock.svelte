<script lang="ts">
  import { createBlock, type BlockSummaryDto } from '../../lib/ipc';
  import { userMessageFor, type AppError } from '../../lib/errors';

  let { onCreated, onCancel }: { onCreated: (block: BlockSummaryDto) => void; onCancel: () => void } = $props();
  let name = $state('');
  let submitting = $state(false);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);

  const canCreate = $derived(!submitting); // empty name is allowed (core permits it)

  async function submit(): Promise<void> {
    if (submitting) return;
    submitting = true; errMsg = null;
    try {
      const block = await createBlock(name.trim());
      onCreated(block);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }
</script>

<section class="editor">
  <button type="button" class="editor__back" onclick={onCancel}>← Cancel</button>
  <h2 class="editor__title">New block</h2>
  {#if errMsg}<div class="editor__error" role="alert">{errMsg.title}</div>{/if}
  <label class="editor__field" for="new-block-name"><span>Block name</span>
    <input id="new-block-name" type="text" aria-label="block name" bind:value={name} placeholder="e.g. Work logins" disabled={submitting} />
  </label>
  <div class="editor__actions">
    <button type="button" disabled={!canCreate} onclick={submit}>{submitting ? 'Creating…' : 'Create block'}</button>
  </div>
</section>
