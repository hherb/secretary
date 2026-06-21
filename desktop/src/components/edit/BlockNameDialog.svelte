<script lang="ts">
  import { createBlock, renameBlock, type BlockSummaryDto } from '../../lib/ipc';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import { isBlankName } from '../../lib/blockCrud';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';

  type Mode = { kind: 'create' } | { kind: 'rename'; block: BlockSummaryDto };
  let { mode, onDone, onCancel }: {
    mode: Mode;
    onDone: (block: BlockSummaryDto) => void;
    onCancel: () => void;
  } = $props();

  // mode is stable for the lifetime of this dialog (parent re-mounts per
  // operation); capturing the initial value for the pre-fill is intentional.
  // svelte-ignore state_referenced_locally
  let name = $state(mode.kind === 'rename' ? mode.block.blockName : '');
  let submitting = $state(false);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);

  const isRename = $derived(mode.kind === 'rename');
  const heading = $derived(isRename ? 'Rename block' : 'New block');
  const idleLabel = $derived(isRename ? 'Rename block' : 'Create block');
  const busyLabel = $derived(isRename ? 'Renaming…' : 'Creating…');

  async function submit(): Promise<void> {
    if (submitting) return;
    const trimmed = name.trim();
    // UI policy: reject blank names (create + rename) without an IPC round-trip.
    if (isBlankName(trimmed)) {
      errMsg = { title: 'Block name is required' };
      return;
    }
    submitting = true; errMsg = null;
    const reason = mode.kind === 'rename' ? 'Confirm renaming this block' : 'Confirm creating this block';
    try {
      await authorizeWrite(reason);
    } catch (err) {
      if (err === ReauthCancelled) { submitting = false; return; }
      errMsg = userMessageFor(err as AppError);
      submitting = false;
      return;
    }
    try {
      const block = mode.kind === 'rename'
        ? await renameBlock(mode.block.blockUuidHex, trimmed)
        : await createBlock(trimmed);
      onDone(block);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }
</script>

<section class="editor">
  <button type="button" class="editor__back" onclick={onCancel}>← Cancel</button>
  <h2 class="editor__title">{heading}</h2>
  {#if errMsg}<div class="editor__error" role="alert">{errMsg.title}</div>{/if}
  <label class="editor__field" for="block-name"><span>Block name</span>
    <input id="block-name" type="text" aria-label="block name" bind:value={name} placeholder="e.g. Work logins" disabled={submitting} />
  </label>
  <div class="editor__actions">
    <button type="button" disabled={submitting} onclick={submit}>{submitting ? busyLabel : idleLabel}</button>
  </div>
</section>
