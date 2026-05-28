<script lang="ts">
  import PathPicker from '../components/PathPicker.svelte';
  import { sessionState, beginUnlock, unlockSucceeded, unlockFailed } from '../lib/stores';
  import { unlockWithPassword, getSettings } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';

  let folderPath = $state('');
  let password = $state('');
  let submitting = $state(false);

  const formValid = $derived(folderPath.length > 0 && password.length > 0);

  async function submit(e: SubmitEvent): Promise<void> {
    e.preventDefault();
    if (!formValid || submitting) return;
    submitting = true;
    beginUnlock();
    try {
      const manifest = await unlockWithPassword(folderPath, password);
      // Manifest only carries `warnings`; the full settings DTO comes
      // from `getSettings` so the post-unlock route has the auto-lock
      // timeout (etc.) readily available.
      const settings = await getSettings();
      unlockSucceeded(manifest, settings);
    } catch (err) {
      unlockFailed(err as AppError);
    } finally {
      // Password lifetime ends here regardless of outcome — strip the
      // binding immediately so a failed attempt doesn't leave the string
      // sitting in DOM state across the user's next keystroke. JS strings
      // are immutable so we can't truly zeroize, but unbinding minimises
      // the live-reference window the GC has to chase.
      password = '';
      submitting = false;
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
    <div class="unlock__icon" aria-hidden="true">🔐</div>
    <h1 class="unlock__title">Secretary</h1>
    <p class="unlock__subtitle">Open a vault</p>

    <form onsubmit={submit}>
      {#if errMsg}
        <div class="unlock__error" role="alert">
          <div class="unlock__error-title">{errMsg.title}</div>
          {#if errMsg.detail}
            <div class="unlock__error-detail">{errMsg.detail}</div>
          {/if}
          {#if errMsg.actionHint}
            <div class="unlock__error-hint">{errMsg.actionHint}</div>
          {/if}
        </div>
      {/if}

      <label class="unlock__field">
        <span class="unlock__label">Vault folder</span>
        <PathPicker
          value={folderPath}
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

      <div class="unlock__footer">
        Lost your password? Use recovery phrase (coming soon)
      </div>
    </form>
  </div>
</main>
