<script lang="ts">
  // Centered password re-prompt for "Sync now" (D.1.14). Native <dialog>
  // mirroring ConfirmDialog: callback props, showModal() on mount via
  // $effect, Esc → preventDefault + onCancel so the parent's unmount is the
  // single close route. The mutation is strict: a failure renders the typed
  // AppError inline and keeps the dialog open so the user can retry a
  // mistyped password. The password lives only in this component's state and
  // is cleared on success.
  import { syncNow, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import type { SyncOutcome } from '../lib/sync';

  type Props = {
    onSynced: (outcome: SyncOutcome) => void;
    onCancel: () => void;
  };
  let { onSynced, onCancel }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let password = $state('');
  let busy = $state(false);
  let error = $state<AppError | null>(null);

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  function cancel() {
    password = '';
    onCancel();
  }

  function onNativeCancel(event: Event) {
    event.preventDefault();
    cancel();
  }

  async function submit(event: Event) {
    event.preventDefault();
    if (busy || password.length === 0) return;
    busy = true;
    error = null;
    try {
      const outcome = await syncNow(password);
      password = '';
      onSynced(outcome);
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }
</script>

<dialog bind:this={dialogEl} class="sync-dialog" oncancel={onNativeCancel}>
  <form class="sync-dialog__form" onsubmit={submit}>
    <h2 class="sync-dialog__title">Confirm your password</h2>
    <p class="sync-dialog__subtitle">Needed to sync this vault.</p>

    <label class="sync-dialog__label" for="sync-password">Password</label>
    <!-- svelte-ignore a11y_autofocus -->
    <input
      id="sync-password"
      class="sync-dialog__input"
      type="password"
      autocomplete="current-password"
      autofocus
      bind:value={password}
      disabled={busy}
    />

    {#if error}
      {@const msg = userMessageFor(error)}
      <p class="sync-dialog__error" role="alert">
        {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
      </p>
    {/if}

    <div class="sync-dialog__actions">
      <button type="button" class="sync-dialog__button" onclick={cancel} disabled={busy}>
        Cancel
      </button>
      <button
        type="submit"
        class="sync-dialog__button sync-dialog__button--primary"
        disabled={busy || password.length === 0}
      >
        {busy ? 'Syncing…' : 'Sync'}
      </button>
    </div>
  </form>
</dialog>
