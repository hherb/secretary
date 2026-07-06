<script lang="ts">
  // Write re-auth prompt. Subscribes to the shared `reauthPrompt` store;
  // mounts modally whenever a write needs the password re-confirmed.
  // Design B: the dialog owns the verify + retry UX. A wrong password shows
  // an inline error and keeps the prompt open; a correct password settles
  // the guard via __resolveReauthPrompt (no password argument — the guard
  // does not re-verify). Cancel calls __cancelReauthPrompt which rejects
  // the pending authorizeWrite promise with ReauthCancelled.
  //
  // The $effect showModal/close pattern mirrors SettingsDialog.svelte: the
  // native <dialog> state follows the store. Escape fires onclose which
  // delegates to cancel() when a prompt is active.
  import { reauthPrompt } from '../lib/stores';
  import { verifyPassword, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import { __resolveReauthPrompt, __cancelReauthPrompt } from '../lib/writeGuard';

  let dialogEl: HTMLDialogElement | undefined = $state();
  let password = $state('');
  let formError = $state<AppError | null>(null);
  let submitting = $state(false);

  let prompt = $derived($reauthPrompt);

  $effect(() => {
    if (!dialogEl) return;
    if (prompt && !dialogEl.hasAttribute('open')) {
      password = '';
      formError = null;
      dialogEl.showModal();
    } else if (!prompt && dialogEl.hasAttribute('open')) {
      dialogEl.close();
    }
  });

  async function confirm() {
    submitting = true;
    formError = null;
    try {
      await verifyPassword(password);
      password = '';
      __resolveReauthPrompt();
    } catch (err) {
      formError = isAppError(err) ? err : { code: 'internal' };
    } finally {
      submitting = false;
    }
  }

  function cancel() {
    password = '';
    formError = null;
    __cancelReauthPrompt();
  }

  // Native `close` event fires on Escape in a real browser as well as
  // when our $effect calls dialogEl.close(). Only treat as cancel when
  // the prompt is still active — if it's already null the guard already
  // initiated the close and re-running cancel is redundant.
  function onNativeClose() {
    if (prompt) cancel();
  }
</script>

<dialog
  bind:this={dialogEl}
  class="reauth-dialog"
  aria-labelledby="reauth-dialog-title"
  onclose={onNativeClose}
>
  {#if prompt}
    <h2 id="reauth-dialog-title" class="reauth-dialog__title">Confirm with your password</h2>
    <p class="reauth-dialog__reason">{prompt.reason}</p>
    <label class="reauth-dialog__field">
      <span class="reauth-dialog__label">Password</span>
      <input
        type="password"
        class="reauth-dialog__input"
        bind:value={password}
        disabled={submitting}
        autocomplete="current-password"
      />
    </label>
    {#if formError}
      {@const msg = userMessageFor(formError)}
      <div class="reauth-dialog__error" role="alert">
        <strong>{msg.title}</strong>
        {#if msg.actionHint}<div class="reauth-dialog__hint">{msg.actionHint}</div>{/if}
      </div>
    {/if}
    <div class="reauth-dialog__actions">
      <button type="button" onclick={cancel} disabled={submitting}>Cancel</button>
      <button
        type="button"
        class="reauth-dialog__button--primary"
        onclick={confirm}
        disabled={submitting}
      >
        {submitting ? 'Verifying…' : 'Confirm'}
      </button>
    </div>
  {/if}
</dialog>
