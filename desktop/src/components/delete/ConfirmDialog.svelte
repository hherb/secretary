<script lang="ts">
  // Shared destructive-action confirm modal (delete record, trash block).
  // Native <dialog> mirroring SettingsDialog's pattern, but driven by
  // callback props (onConfirm / onCancel) rather than a bindable `open` —
  // the parent mounts the dialog only while a confirmation is pending and
  // unmounts it on either resolution, so there is no closed state to model.
  //
  // Contract (pinned by ConfirmDialog.test.ts):
  //   - showModal() on mount via $effect (the dialog only exists when open).
  //   - Confirm button is labelled with `confirmLabel` and fires onConfirm.
  //   - Cancel button fires onCancel.
  //   - Esc (native `cancel` event) → preventDefault + onCancel, so the
  //     parent's unmount path is the single close route (no double-close).

  type Props = {
    title: string;
    body: string;
    confirmLabel: string;
    onConfirm: () => void;
    onCancel: () => void;
  };
  let { title, body, confirmLabel, onConfirm, onCancel }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  // Esc dismiss: the native `cancel` event precedes the `close` event.
  // Prevent the default close so the only teardown path is the parent
  // unmounting in response to onCancel — keeps a single source of truth
  // for the dialog's lifetime.
  function onNativeCancel(event: Event) {
    event.preventDefault();
    onCancel();
  }
</script>

<dialog
  bind:this={dialogEl}
  class="confirm-dialog"
  aria-labelledby="confirm-dialog-title"
  oncancel={onNativeCancel}
>
  <h2 id="confirm-dialog-title" class="confirm-dialog__title">{title}</h2>
  <p class="confirm-dialog__body">{body}</p>

  <div class="confirm-dialog__actions">
    <button type="button" class="confirm-dialog__button" onclick={onCancel}>
      Cancel
    </button>
    <button
      type="button"
      class="confirm-dialog__button confirm-dialog__button--danger"
      onclick={onConfirm}
    >
      {confirmLabel}
    </button>
  </div>
</dialog>
