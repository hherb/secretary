<script lang="ts">
  // Settings dialog — native <dialog> overlay for editing app settings.
  // Edits auto-lock timeout (minutes), write re-auth toggle and grace window,
  // the trash retention window (days), and — macOS only, #277 — the
  // desktop-local "Use Touch ID on this Mac" preference. Validation + save
  // flow kept generic for future fields.
  //
  // Contract (pinned by SettingsDialog.test.ts):
  //   - Parent toggles `open` (bindable). $effect drives showModal/close
  //     so the native <dialog> state stays in sync.
  //   - Initial input value is pre-populated from currentSettings (or
  //     AUTO_LOCK_DEFAULT_MS in minutes if locked — defensive only).
  //   - Save: validate → setSettings IPC (ms) → settingsUpdated → (if the
  //     Touch ID toggle changed) writePresencePref IPC → setPresencePref →
  //     onClose. A writePresencePref rejection surfaces via formError and
  //     does NOT roll back the already-persisted vault settings — see #277.
  //   - Cancel: revert local edit, then onClose.
  //   - Validation failures and IPC rejections both render via
  //     userMessageFor on the same typed AppError union for consistency.
  //   - The Touch ID toggle only renders when `$presencePref.availability
  //     === 'available'`; the save-time pref write is independently guarded
  //     on the same condition so a hidden toggle can never write the pref.

  import { sessionState, settingsUpdated, presencePref, setPresencePref } from '../lib/stores';
  import { setSettings, isAppError, writePresencePref } from '../lib/ipc';
  import { authorizeWrite, ReauthCancelled } from '../lib/writeGuard';
  import { userMessageFor, type AppError } from '../lib/errors';
  import {
    MS_PER_MINUTE,
    MS_PER_DAY,
    AUTO_LOCK_MIN_MS,
    AUTO_LOCK_MAX_MS,
    AUTO_LOCK_DEFAULT_MS,
    REAUTH_WINDOW_MIN_MS,
    REAUTH_WINDOW_MAX_MS,
    REAUTH_WINDOW_DEFAULT_MS,
    REQUIRE_PASSWORD_DEFAULT,
    RETENTION_WINDOW_MIN_MS,
    RETENTION_WINDOW_MAX_MS,
    RETENTION_WINDOW_DEFAULT_MS
  } from '../lib/constants';

  type Props = {
    open: boolean;
    onClose: () => void;
  };
  let { open = $bindable(), onClose }: Props = $props();

  const MIN_MINUTES = AUTO_LOCK_MIN_MS / MS_PER_MINUTE;
  const MAX_MINUTES = AUTO_LOCK_MAX_MS / MS_PER_MINUTE;
  const DEFAULT_MINUTES = AUTO_LOCK_DEFAULT_MS / MS_PER_MINUTE;

  const WINDOW_MIN_MINUTES = REAUTH_WINDOW_MIN_MS / MS_PER_MINUTE;
  const WINDOW_MAX_MINUTES = REAUTH_WINDOW_MAX_MS / MS_PER_MINUTE;
  const WINDOW_DEFAULT_MINUTES = REAUTH_WINDOW_DEFAULT_MS / MS_PER_MINUTE;

  const RETENTION_MIN_DAYS = RETENTION_WINDOW_MIN_MS / MS_PER_DAY;
  const RETENTION_MAX_DAYS = RETENTION_WINDOW_MAX_MS / MS_PER_DAY;
  const RETENTION_DEFAULT_DAYS = RETENTION_WINDOW_DEFAULT_MS / MS_PER_DAY;

  // Source-of-truth for the displayed values is the current store; the
  // dialog is a thin editor. The $derived means re-opening after a
  // store change (e.g. a sync push from another device, when D.2 lands)
  // shows the fresh value rather than the stale on-mount snapshot.
  let currentMs = $derived(
    $sessionState.status === 'unlocked'
      ? $sessionState.settings.autoLockTimeoutMs
      : AUTO_LOCK_DEFAULT_MS
  );

  let currentRequirePassword = $derived(
    $sessionState.status === 'unlocked'
      ? $sessionState.settings.requirePasswordBeforeEdits
      : REQUIRE_PASSWORD_DEFAULT
  );

  let currentWindowMs = $derived(
    $sessionState.status === 'unlocked'
      ? $sessionState.settings.reauthGraceWindowMs
      : REAUTH_WINDOW_DEFAULT_MS
  );

  let currentRetentionMs = $derived(
    $sessionState.status === 'unlocked'
      ? $sessionState.settings.retentionWindowMs
      : RETENTION_WINDOW_DEFAULT_MS
  );

  // Desktop-local, this-device preference (#277) — independent of the
  // vault-synced `sessionState.settings` above, so no locked-session
  // fallback: `presencePref`'s own safe default (biometricEnabled: false,
  // availability: 'unsupported') already covers the not-loaded case.
  let biometricAvailable = $derived($presencePref.availability === 'available');
  let currentBiometric = $derived($presencePref.biometricEnabled);

  let inputMinutes = $state(DEFAULT_MINUTES);
  let inputRequirePassword = $state(REQUIRE_PASSWORD_DEFAULT);
  let inputWindowMinutes = $state(WINDOW_DEFAULT_MINUTES);
  let inputRetentionDays = $state(RETENTION_DEFAULT_DAYS);
  let inputBiometric = $state(false);
  let formError = $state<AppError | null>(null);
  let submitting = $state(false);
  let dialogEl: HTMLDialogElement | undefined = $state();

  // Re-seed the inputs from the store values whenever the store changes
  // OR the dialog re-opens. The latter handles the user typing 7,
  // pressing Cancel, then re-opening — they should see the persisted
  // value again, not their abandoned edit.
  $effect(() => {
    void open;
    inputMinutes = Math.round(currentMs / MS_PER_MINUTE);
    inputRequirePassword = currentRequirePassword;
    inputWindowMinutes = Math.round(currentWindowMs / MS_PER_MINUTE);
    inputRetentionDays = Math.round(currentRetentionMs / MS_PER_DAY);
    inputBiometric = currentBiometric;
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
    if (
      !Number.isInteger(inputWindowMinutes) ||
      inputWindowMinutes < WINDOW_MIN_MINUTES ||
      inputWindowMinutes > WINDOW_MAX_MINUTES
    ) {
      return {
        code: 'settings_out_of_range',
        min: REAUTH_WINDOW_MIN_MS,
        max: REAUTH_WINDOW_MAX_MS
      };
    }
    if (
      !Number.isInteger(inputRetentionDays) ||
      inputRetentionDays < RETENTION_MIN_DAYS ||
      inputRetentionDays > RETENTION_MAX_DAYS
    ) {
      return {
        code: 'settings_out_of_range',
        min: RETENTION_WINDOW_MIN_MS,
        max: RETENTION_WINDOW_MAX_MS
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
    const newSettings = {
      autoLockTimeoutMs: inputMinutes * MS_PER_MINUTE,
      requirePasswordBeforeEdits: inputRequirePassword,
      reauthGraceWindowMs: inputWindowMinutes * MS_PER_MINUTE,
      retentionWindowMs: inputRetentionDays * MS_PER_DAY
    };
    const nextBiometric = inputBiometric; // snapshot beside newSettings — the $effect
    // re-seed can clobber inputBiometric mid-save (settingsUpdated moves the
    // $derived current* values, which re-runs the input-re-seeding $effect
    // during a later await), so every read below uses this snapshot.
    submitting = true;
    formError = null;

    // Gate security-REDUCING settings changes behind the same write re-auth as
    // any other mutating write. Without this, an attacker at an unlocked-but-
    // unattended session could weaken protection here to buy a longer window.
    // `authorizeWrite` reads the CURRENT (pre-save) policy, so within the live
    // grace window it resolves silently — consistent with every other write.
    //
    // Three independent reductions:
    //  - Weakening the write-reauth gate: disabling it or widening its grace
    //    window. Only matters when the gate is currently effective.
    //  - Widening the auto-lock timeout (#363): keeps the vault unlocked longer,
    //    a reduction regardless of the write-reauth policy — so it is NOT gated
    //    on `currentRequirePassword`.
    //  - Enabling Touch ID (#277): adds a compellable presence-proof path to
    //    the write-reauth gate — a reduction. Disabling it is a hardening
    //    (the travel kill-switch) and must NOT require re-auth by itself.
    const widensAutoLock = newSettings.autoLockTimeoutMs > currentMs;
    const weakensWriteGate =
      currentRequirePassword &&
      (!newSettings.requirePasswordBeforeEdits ||
        newSettings.reauthGraceWindowMs > currentWindowMs);
    const enablesBiometric = nextBiometric && !currentBiometric;
    const reducesProtection = widensAutoLock || weakensWriteGate || enablesBiometric;
    if (reducesProtection) {
      try {
        await authorizeWrite('Confirm changing the write re-auth setting');
      } catch (err) {
        if (err === ReauthCancelled) {
          submitting = false;
          return;
        }
        formError = isAppError(err) ? err : { code: 'internal' };
        submitting = false;
        return;
      }
    }

    try {
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
      // Persist the Touch ID preference only when it actually changed, and
      // only when the toggle could have been shown at all — a hidden toggle
      // (biometry unavailable) must never write the pref, even defensively.
      // A rejection here surfaces via the catch below WITHOUT rolling back
      // the vault settings write above (partial-save: the dialog stays open
      // showing the error, and the vault settings the user just saved stay
      // saved — but note that when the save also changed a vault setting,
      // the $effect re-seed has reverted the checkbox to the store value by
      // then, so the user must re-toggle it before re-running Save).
      if (biometricAvailable && nextBiometric !== currentBiometric) {
        await writePresencePref(nextBiometric);
        setPresencePref({ biometricEnabled: nextBiometric, availability: $presencePref.availability });
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
    inputRequirePassword = currentRequirePassword;
    inputWindowMinutes = Math.round(currentWindowMs / MS_PER_MINUTE);
    inputRetentionDays = Math.round(currentRetentionMs / MS_PER_DAY);
    inputBiometric = currentBiometric;
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

<dialog
  bind:this={dialogEl}
  class="settings-dialog"
  aria-labelledby="settings-dialog-title"
  onclose={onNativeClose}
>
  <h2 id="settings-dialog-title" class="settings-dialog__title">Settings</h2>

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

  <label class="settings-dialog__field settings-dialog__field--checkbox">
    <input
      type="checkbox"
      class="settings-dialog__checkbox"
      bind:checked={inputRequirePassword}
      disabled={submitting}
    />
    <span class="settings-dialog__label">Require password before edits</span>
  </label>

  {#if biometricAvailable}
    <label class="settings-dialog__field settings-dialog__field--checkbox">
      <input
        type="checkbox"
        class="settings-dialog__checkbox"
        bind:checked={inputBiometric}
        disabled={submitting}
      />
      <span class="settings-dialog__label">Use Touch ID on this Mac</span>
    </label>
    <p class="settings-dialog__hint">
      Applies to this device only. Turn off before travelling through high-risk areas —
      a password will always be required instead.
    </p>
  {/if}

  <label class="settings-dialog__field">
    <span class="settings-dialog__label">Re-authentication grace window</span>
    <div class="settings-dialog__input-row">
      <input
        type="number"
        class="settings-dialog__input"
        min={WINDOW_MIN_MINUTES}
        max={WINDOW_MAX_MINUTES}
        step="1"
        bind:value={inputWindowMinutes}
        disabled={submitting}
      />
      <span class="settings-dialog__suffix">minutes</span>
    </div>
  </label>

  <label class="settings-dialog__field">
    <span class="settings-dialog__label">Retention window</span>
    <div class="settings-dialog__input-row">
      <input
        type="number"
        class="settings-dialog__input"
        min={RETENTION_MIN_DAYS}
        max={RETENTION_MAX_DAYS}
        step="1"
        bind:value={inputRetentionDays}
        disabled={submitting}
      />
      <span class="settings-dialog__suffix">days</span>
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
