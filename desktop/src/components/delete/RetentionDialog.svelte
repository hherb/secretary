<script lang="ts">
  // Two-step retention dialog (reached from Settings' "Run retention now").
  // Step 1: preview which trashed blocks are past the window (calls
  // previewRetention on mount, mirrors TrashView's load/error shape).
  // Step 2: an irreversible bulk purge, gated behind the same
  // authorizeWrite chokepoint as every other write, then runRetention,
  // then refreshManifest, then onClose. Mounts only while open (parent
  // controls mount, like ConfirmDialog) — no bindable `open` prop and no
  // closed state to model.
  //
  // NOTE for future edits: don't write a wrapper name followed by `(` in a
  // comment above — the write-gate coverage scanner (writeGateScanner.ts,
  // #280) is comment-naive for call detection and will flag it as an
  // ungated top-level call.

  import { previewRetention, runRetention, isAppError, type RetentionPreviewDto } from '../../lib/ipc';
  import { retentionSummary } from '../../lib/retention';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';
  import { refreshManifest } from '../../lib/stores';
  import { userMessageFor, type AppError } from '../../lib/errors';

  type Props = { onClose: () => void };
  let { onClose }: Props = $props();

  let preview = $state<RetentionPreviewDto | null>(null);
  let error = $state<AppError | null>(null);
  let submitting = $state(false);
  let dialogEl: HTMLDialogElement | undefined = $state();

  // Generation guard (see TrashView / RecordList): only the newest load()
  // call is allowed to write `preview` / `error`.
  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    error = null;
    try {
      const p = await previewRetention();
      if (seq === loadSeq) preview = p;
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) dialogEl.showModal();
  });
  $effect(() => {
    void load();
  });

  function onNativeCancel(event: Event) {
    event.preventDefault();
    onClose();
  }

  let summary = $derived(preview ? retentionSummary(preview.entries, preview.windowMs) : '');
  let hasExpired = $derived((preview?.entries.length ?? 0) > 0);

  async function confirm() {
    error = null;
    try {
      await authorizeWrite('Confirm permanently deleting expired trash');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    submitting = true;
    try {
      await runRetention();
      await refreshManifest();
      onClose();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    } finally {
      submitting = false;
    }
  }
</script>

<dialog
  bind:this={dialogEl}
  class="retention-dialog"
  aria-labelledby="retention-dialog-title"
  oncancel={onNativeCancel}
>
  <h2 id="retention-dialog-title" class="retention-dialog__title">Run retention now</h2>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="retention-dialog__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if preview === null}
    <p class="retention-dialog__loading">Checking trash…</p>
  {:else}
    <p class="retention-dialog__summary">{summary}</p>
  {/if}

  <div class="retention-dialog__actions">
    <button type="button" class="retention-dialog__button" onclick={onClose} disabled={submitting}>
      {hasExpired ? 'Cancel' : 'Close'}
    </button>
    {#if hasExpired}
      <button
        type="button"
        class="retention-dialog__button retention-dialog__button--danger"
        onclick={confirm}
        disabled={submitting}
      >
        {submitting ? 'Purging…' : `Purge ${preview?.entries.length} items`}
      </button>
    {/if}
  </div>
</dialog>
