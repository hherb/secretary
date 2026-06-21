<script lang="ts">
  // Settings dialog — native <dialog> overlay for editing app settings.
  // Currently one field (auto-lock timeout in minutes); structured for
  // future fields by keeping the validation + save flow generic.
  //
  // Contract (pinned by SettingsDialog.test.ts):
  //   - Parent toggles `open` (bindable). $effect drives showModal/close
  //     so the native <dialog> state stays in sync.
  //   - Initial input value is pre-populated from currentSettings (or
  //     AUTO_LOCK_DEFAULT_MS in minutes if locked — defensive only).
  //   - Save: validate → setSettings IPC (ms) → settingsUpdated → onClose.
  //   - Cancel: revert local edit, then onClose.
  //   - Validation failures and IPC rejections both render via
  //     userMessageFor on the same typed AppError union for consistency.

  import { sessionState, settingsUpdated } from '../lib/stores';
  import { setSettings, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import {
    MS_PER_MINUTE,
    AUTO_LOCK_MIN_MS,
    AUTO_LOCK_MAX_MS,
    AUTO_LOCK_DEFAULT_MS
  } from '../lib/constants';

  type Props = {
    open: boolean;
    onClose: () => void;
  };
  let { open = $bindable(), onClose }: Props = $props();

  const MIN_MINUTES = AUTO_LOCK_MIN_MS / MS_PER_MINUTE;
  const MAX_MINUTES = AUTO_LOCK_MAX_MS / MS_PER_MINUTE;
  const DEFAULT_MINUTES = AUTO_LOCK_DEFAULT_MS / MS_PER_MINUTE;

  // Source-of-truth for the displayed value is the current store; the
  // dialog is a thin editor. The $derived means re-opening after a
  // store change (e.g. a sync push from another device, when D.2 lands)
  // shows the fresh value rather than the stale on-mount snapshot.
  let currentMs = $derived(
    $sessionState.status === 'unlocked'
      ? $sessionState.settings.autoLockTimeoutMs
      : AUTO_LOCK_DEFAULT_MS
  );

  let inputMinutes = $state(DEFAULT_MINUTES);
  let formError = $state<AppError | null>(null);
  let submitting = $state(false);
  let dialogEl: HTMLDialogElement | undefined = $state();

  // Re-seed the input from the store value whenever the store changes
  // OR the dialog re-opens. The latter handles the user typing 7,
  // pressing Cancel, then re-opening — they should see the persisted
  // value again, not their abandoned edit.
  $effect(() => {
    void open;
    inputMinutes = Math.round(currentMs / MS_PER_MINUTE);
    formError = null;
  });

  $effect(() => {
    if (!dialogEl) return;
    if (open && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    } else if (!open && dialogEl.hasAttribute('open')) {
      dialogEl.close();
    }
  });

  function validateOrError(): AppError | null {
    if (
      !Number.isInteger(inputMinutes) ||
      inputMinutes < MIN_MINUTES ||
      inputMinutes > MAX_MINUTES
    ) {
      return {
        code: 'settings_out_of_range',
        min: AUTO_LOCK_MIN_MS,
        max: AUTO_LOCK_MAX_MS
      };
    }
    return null;
  }

  async function save() {
    const validationErr = validateOrError();
    if (validationErr) {
      formError = validationErr;
      return;
    }
    submitting = true;
    formError = null;
    try {
      const newMs = inputMinutes * MS_PER_MINUTE;
      // Spread the full current settings and override only the edited
      // field — keeps the other settings (requirePasswordBeforeEdits,
      // reauthGraceWindowMs) intact and satisfies SettingsDto's shape.
      const current = $sessionState.status === 'unlocked' ? $sessionState.settings : null;
      const newSettings = { ...(current ?? { requirePasswordBeforeEdits: false, reauthGraceWindowMs: 120_000 }), autoLockTimeoutMs: newMs };
      await setSettings(newSettings);
      // Race-guard: a vault-locked event may arrive between the IPC
      // firing and resolving (auto-lock at the boundary). In that case
      // the session has already left `unlocked` and `settingsUpdated`
      // would throw via the illegal-transition guard. The backend has
      // persisted the new value either way, so the next unlock observes
      // it — skipping the in-memory update here is safe.
      if ($sessionState.status === 'unlocked') {
        settingsUpdated(newSettings);
      }
      onClose();
    } catch (err) {
      // call() in ipc.ts already coerces non-AppError rejections, but
      // narrow locally too so the component contract holds without
      // depending on the IPC layer's error-mapping behaviour.
      formError = isAppError(err) ? err : { code: 'internal' };
      if (!isAppError(err)) {
        console.error('SettingsDialog: non-AppError rejection from setSettings', err);
      }
    } finally {
      submitting = false;
    }
  }

  function cancel() {
    formError = null;
    inputMinutes = Math.round(currentMs / MS_PER_MINUTE);
    onClose();
  }

  // The native `close` event fires both when our $effect calls
  // dialogEl.close() (after save/cancel set `open` to false) AND when
  // the user dismisses with Escape in a real browser. Only run cancel
  // in the latter case — if `open` is already false the parent already
  // initiated the close and re-running cancel is redundant. Without
  // this guard, any future side-effect added to cancel() (telemetry,
  // optimistic revert, etc.) would fire spuriously on every Save.
  function onNativeClose() {
    if (open) cancel();
  }
</script>

<dialog bind:this={dialogEl} class="settings-dialog" onclose={onNativeClose}>
  <h2 class="settings-dialog__title">Settings</h2>

  <label class="settings-dialog__field">
    <span class="settings-dialog__label">Auto-lock after</span>
    <div class="settings-dialog__input-row">
      <input
        type="number"
        class="settings-dialog__input"
        min={MIN_MINUTES}
        max={MAX_MINUTES}
        step="1"
        bind:value={inputMinutes}
        disabled={submitting}
      />
      <span class="settings-dialog__suffix">minutes</span>
    </div>
  </label>

  {#if formError}
    {@const msg = userMessageFor(formError)}
    <div class="settings-dialog__error" role="alert">
      <strong>{msg.title}</strong>
      {#if msg.detail}<div class="settings-dialog__error-detail">{msg.detail}</div>{/if}
    </div>
  {/if}

  <div class="settings-dialog__actions">
    <button type="button" class="settings-dialog__button" onclick={cancel} disabled={submitting}>
      Cancel
    </button>
    <button
      type="button"
      class="settings-dialog__button settings-dialog__button--primary"
      onclick={save}
      disabled={submitting}
    >
      {submitting ? 'Saving…' : 'Save'}
    </button>
  </div>
</dialog>
