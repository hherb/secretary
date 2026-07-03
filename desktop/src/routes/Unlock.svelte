<script lang="ts">
  import LockKeyhole from '../components/icons/LockKeyhole.svelte';
  import PathPicker from '../components/PathPicker.svelte';
  import { sessionState, beginUnlock, unlockSucceeded, unlockFailed } from '../lib/stores';
  import { unlockWithPassword, repairVault, getSettings, isAppError } from '../lib/ipc';
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
  // failed unlock's `finally` deliberately did not clear it). Whatever the
  // outcome, the password is no longer needed afterwards, so it is always
  // cleared here: success proceeds into the unlocked session, and
  // `repair_rejected` has no auto-fix retry that would need it again.
  async function confirmRepair(): Promise<void> {
    if (submitting) return;
    submitting = true;
    // Keep the repair affordance mounted while repair runs — see `repairing`.
    repairing = true;
    // Repair funnels through the same locked→unlocking→{unlocked,locked}
    // session-state machine as a normal unlock (see stores.ts) — both
    // `unlockSucceeded` and `unlockFailed` below require the `unlocking`
    // state as their `from`.
    beginUnlock();
    try {
      const manifest = await repairVault(folderPath, password);
      const settings = await getSettings();
      unlockSucceeded(manifest, settings);
      seedReauthClock(Date.now());
    } catch (err) {
      unlockFailed(err);
    } finally {
      password = '';
      submitting = false;
      repairing = false;
    }
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
            disabled={submitting}
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
</main>
