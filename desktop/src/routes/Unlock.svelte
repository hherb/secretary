<script lang="ts">
  import LockKeyhole from '../components/icons/LockKeyhole.svelte';
  import PathPicker from '../components/PathPicker.svelte';
  import RepairConsentDialog from '../components/RepairConsentDialog.svelte';
  import { sessionState, beginUnlock, unlockSucceeded, unlockFailed } from '../lib/stores';
  import {
    unlockWithPassword,
    repairVault,
    previewRepair,
    getSettings,
    isAppError,
    type ApprovedWideningDto,
    type WideningReportDto
  } from '../lib/ipc';
  import type { AppError } from '../lib/errors';
  import { userMessageFor } from '../lib/errors';
  import { seedReauthClock } from '../lib/writeGuard';
  import { openCreateWizard, createdVaultPath } from '../lib/route';
  import { get } from 'svelte/store';

  let folderPath = $state('');

  // Pre-fill from a just-created vault (set by finishCreateWizard), then
  // consume the store so the banner is strictly one-shot: Unlock remounts on
  // every appRoute switch and on every lock, so without clearing, the
  // "Vault created" banner would replay on a later unrelated unlock. The
  // svelte-check state_referenced_locally note on `created`/showCreatedBanner
  // is expected — the read is intentionally a one-time mount-time capture.
  const created = get(createdVaultPath);
  if (created.length > 0) {
    // svelte-ignore state_referenced_locally
    if (folderPath.length === 0) {
      folderPath = created;
    }
    createdVaultPath.set('');
  }
  const showCreatedBanner = $derived(created.length > 0);

  // Is the current error the "not a vault" case? Then offer to create here.
  const offerCreate = $derived(
    $sessionState.status === 'locked' &&
      $sessionState.lastError?.code === 'vault_path_not_a_vault'
  );

  // #374: the open failed because the vault has adoptable crash residue.
  // Render a "Repair now?" affordance instead of a hard error.
  const needsRepair = $derived(
    $sessionState.status === 'locked' &&
      $sessionState.lastError?.code === 'vault_needs_repair'
  );

  let password = $state('');
  let submitting = $state(false);

  // #374: true only while `confirmRepair` is in flight. `needsRepair` is
  // derived from session state and goes false the moment `beginUnlock()`
  // transitions `locked → unlocking`, which would otherwise unmount the
  // repair affordance the instant repair starts — hiding the `Repairing…`
  // progress state during the (Argon2id-slow) repair. Keeping the block
  // mounted on `needsRepair || repairing` lets the in-flight state render.
  let repairing = $state(false);

  // #374 Task 10: the widenings a `previewRepair` call found that need
  // informed consent before `repairVault` may adopt them. Non-empty renders
  // `RepairConsentDialog` (see the template) while the session stays
  // `unlocking` (see `repairing` above for why that keeps the affordance
  // block mounted underneath). Built from `previewRepair`'s own response and
  // never mutated field-by-field — `onGrantConsent` reads it verbatim to
  // build the approvals passed to `repairVault`.
  let consentWidenings: WideningReportDto[] = $state([]);

  // The `vault_needs_repair` error captured just before `confirmRepair`'s
  // `beginUnlock()` clears it from session state. `onCancelConsent` restores
  // it via `unlockFailed(priorRepairError)` so Cancel returns to exactly the
  // locked-with-affordance state the user started from, even though the
  // consent dialog may have been open for an arbitrarily long time (the user
  // reviewing the recipient list) since that capture.
  let priorRepairError: AppError | null = null;

  const formValid = $derived(folderPath.length > 0 && password.length > 0);

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!formValid || submitting) return;
    submitting = true;
    beginUnlock();
    // #374: on `vault_needs_repair`, the "Repair now?" affordance reuses this
    // same password to call repairVault — keep the binding alive for that one
    // case. Every other outcome (success or any other error) clears it below,
    // same as before.
    let keepPassword = false;
    try {
      const manifest = await unlockWithPassword(folderPath, password);
      // Manifest only carries `warnings`; the full settings DTO comes
      // from `getSettings` so the post-unlock route has the auto-lock
      // timeout (etc.) readily available.
      const settings = await getSettings();
      unlockSucceeded(manifest, settings);
      // Seed the reauth grace-window clock: the unlock password proves
      // presence, so a write within the grace window should not re-prompt.
      seedReauthClock(Date.now());
    } catch (err) {
      // `unlockFailed` accepts `unknown` and narrows internally; no cast
      // required at the call site.
      unlockFailed(err);
      keepPassword = isAppError(err) && err.code === 'vault_needs_repair';
    } finally {
      // Password lifetime ends here regardless of outcome (unless the
      // repair affordance needs it) — strip the binding immediately so a
      // failed attempt doesn't leave the string sitting in DOM state across
      // the user's next keystroke. JS strings are immutable so we can't
      // truly zeroize, but unbinding minimises the live-reference window
      // the GC has to chase.
      if (!keepPassword) password = '';
      submitting = false;
    }
  }

  // #374: confirm the "Repair now?" affordance. Reuses `folderPath` +
  // `password` still bound to the form (see `keepPassword` above — the
  // failed unlock's `finally` deliberately did not clear it).
  //
  // #374 Task 10: this is a preview-then-repair flow, not a direct repair.
  // `previewRepair` (read-only, no vault mutation) runs first; a clean
  // preview (no widenings) repairs immediately with `[]` approvals — byte-
  // for-byte the same as the pre-Task-10 behavior. A preview that finds
  // widenings instead surfaces `RepairConsentDialog` and waits for the user:
  // `onGrantConsent` repairs with approvals built verbatim from the preview;
  // `onCancelConsent` restores the locked-with-affordance state without
  // calling `repairVault` at all.
  async function confirmRepair(): Promise<void> {
    // #374: guard on `formValid` like `submit` does, not just `submitting`.
    // `needsRepair` is derived from persistent session state, but `password`
    // is component-local $state that resets to '' on remount (e.g. routing to
    // the create wizard and back). Without this guard the still-visible
    // "Repair now" button could fire `repairVault(folderPath, '')` with an
    // empty password, producing a spurious wrong-password/corrupt error.
    if (!formValid || submitting) return;
    // Capture BEFORE beginUnlock() clears `$sessionState.lastError` — this is
    // the only point at which the `vault_needs_repair` error is still live in
    // session state.
    priorRepairError = $sessionState.status === 'locked' ? $sessionState.lastError : null;
    submitting = true;
    // Keep the repair affordance mounted while repair runs — see `repairing`.
    repairing = true;
    // Repair funnels through the same locked→unlocking→{unlocked,locked}
    // session-state machine as a normal unlock (see stores.ts) — both
    // `unlockSucceeded` and `unlockFailed` below require the `unlocking`
    // state as their `from`.
    beginUnlock();
    try {
      const preview = await previewRepair(folderPath, password);
      if (preview.widenings.length === 0) {
        await finishRepair([]);
      } else {
        // Render RepairConsentDialog (see the template) and wait for
        // onGrantConsent / onCancelConsent — `finally` below is deliberately
        // NOT reached yet, so `submitting`/`repairing` stay true and the
        // password stays bound while the user reviews the widenings.
        consentWidenings = preview.widenings;
      }
    } catch (err) {
      unlockFailed(err);
      password = '';
      submitting = false;
      repairing = false;
    }
  }

  // Shared tail of the repair flow for both the no-consent-needed path and
  // the post-Grant path: calls `repairVault` with the given approvals,
  // proceeds into the unlocked session on success, and always resets the
  // in-flight UI state (password, submitting, repairing, consent dialog)
  // afterwards regardless of outcome.
  async function finishRepair(approvals: ApprovedWideningDto[]): Promise<void> {
    try {
      const manifest = await repairVault(folderPath, password, approvals);
      const settings = await getSettings();
      unlockSucceeded(manifest, settings);
      seedReauthClock(Date.now());
    } catch (err) {
      unlockFailed(err);
    } finally {
      password = '';
      submitting = false;
      repairing = false;
      consentWidenings = [];
    }
  }

  // RepairConsentDialog's Grant callback. The approvals are built VERBATIM
  // from the preview's own fields (`blockUuidHex`, `fileFingerprintHex`,
  // `committedFingerprintHex`, `added[].uuidHex`) — never recomputed or
  // edited — because the file-fingerprint + committed-fingerprint binds
  // are exactly what prove the approval matches the recipient set and the
  // committed state the user was shown (#391).
  function onGrantConsent(): void {
    const approvals: ApprovedWideningDto[] = consentWidenings.map((w) => ({
      blockUuidHex: w.blockUuidHex,
      fileFingerprintHex: w.fileFingerprintHex,
      committedFingerprintHex: w.committedFingerprintHex,
      addedUuidsHex: w.added.map((a) => a.uuidHex)
    }));
    consentWidenings = [];
    void finishRepair(approvals);
  }

  // RepairConsentDialog's Cancel callback. No `repairVault` call at all —
  // the vault is untouched. Restores the `vault_needs_repair` error captured
  // at the top of `confirmRepair` so the "Repair now?" affordance re-renders,
  // and deliberately does NOT clear `password` — the affordance reuses it
  // exactly like the initial failed-unlock path does.
  function onCancelConsent(): void {
    consentWidenings = [];
    submitting = false;
    repairing = false;
    unlockFailed(priorRepairError);
  }

  // Inline error: render the userMessageFor() shape of the last unlock
  // failure. `$sessionState` is the Svelte auto-subscription accessor;
  // it narrows on `.status` so reading `.lastError` is type-safe.
  let errMsg = $derived(
    $sessionState.status === 'locked' && $sessionState.lastError
      ? userMessageFor($sessionState.lastError)
      : null
  );
</script>

<!-- Styles for `.unlock*` live in `src/theme.css`; component-scoped
     <style> blocks trip a Vite-6 preprocessCSS bug under Vitest, so all
     visual rules are centralised. -->
<main class="unlock">
  <div class="unlock__card">
    <div class="unlock__icon" aria-hidden="true"><LockKeyhole size={48} /></div>
    <h1 class="unlock__title">Secretary</h1>
    <p class="unlock__subtitle">Open a vault</p>

    <form onsubmit={submit}>
      {#if showCreatedBanner}
        <div class="unlock__banner" role="status">
          Vault created — enter your password to open it.
        </div>
      {/if}

      {#if needsRepair || repairing}
        <!-- #374: an interrupted write left adoptable crash residue — offer
             an in-place fix instead of a hard error. `confirmRepair` reuses
             the password still bound to the form field below. `|| repairing`
             keeps this block mounted while repair is in flight (session state
             is `unlocking` then, so `needsRepair` alone would drop it and hide
             the `Repairing…` progress state). -->
        <div class="unlock__error unlock__repair" role="alert">
          <div class="unlock__error-title">This vault has an interrupted write. Repair now?</div>
          <button
            type="button"
            class="unlock__error-action"
            disabled={submitting || !formValid}
            onclick={confirmRepair}
          >
            {submitting ? 'Repairing…' : 'Repair now'}
          </button>
        </div>
      {:else if errMsg}
        <div class="unlock__error" role="alert">
          <div class="unlock__error-title">{errMsg.title}</div>
          {#if errMsg.detail}
            <div class="unlock__error-detail">{errMsg.detail}</div>
          {/if}
          {#if errMsg.actionHint}
            {#if offerCreate}
              <button
                type="button"
                class="unlock__error-action"
                onclick={() => openCreateWizard(folderPath)}
              >
                Create a vault here
              </button>
            {:else}
              <div class="unlock__error-hint">{errMsg.actionHint}</div>
            {/if}
          {/if}
        </div>
      {/if}

      <label class="unlock__field">
        <span class="unlock__label">Vault folder</span>
        <PathPicker
          value={folderPath}
          command="pick_vault_folder"
          onSelect={(p) => (folderPath = p)}
          disabled={submitting}
        />
      </label>

      <label class="unlock__field">
        <span class="unlock__label">Password</span>
        <input
          type="password"
          class="unlock__password"
          bind:value={password}
          placeholder="••••••••"
          disabled={submitting}
        />
      </label>

      <button type="submit" class="unlock__submit" disabled={!formValid || submitting}>
        {submitting ? 'Unlocking…' : 'Unlock'}
      </button>

      <div class="unlock__divider" aria-hidden="true"><span>or</span></div>

      <!-- First-class create entry point (always visible, unlike the
           contextual "Create a vault here" shown only on a not-a-vault
           error). type="button" so it never submits the unlock form; seeds
           the wizard with whatever folder is currently typed (empty is a
           tested path). Disabled mid-unlock to avoid switching routes while
           an unlock is in flight. -->
      <button
        type="button"
        class="unlock__create"
        disabled={submitting}
        onclick={() => openCreateWizard(folderPath)}
      >
        Create a new vault
      </button>

      <div class="unlock__footer">
        Lost your password? Use recovery phrase (coming soon)
      </div>
    </form>
  </div>

  {#if consentWidenings.length > 0}
    <!-- #374 Task 10: previewRepair found recipient widenings — hold the
         session at `unlocking` (see `repairing` above) and require explicit
         consent before repairVault may adopt them. -->
    <RepairConsentDialog
      widenings={consentWidenings}
      onCancel={onCancelConsent}
      onGrant={onGrantConsent}
    />
  {/if}
</main>
