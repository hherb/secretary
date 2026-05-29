<script lang="ts">
  import { passwordsMatch } from '../../lib/create';

  let {
    folder,
    submitting = false,
    onCreate,
    onBack
  }: {
    folder: string;
    submitting?: boolean;
    onCreate: (displayName: string, password: string) => void | Promise<void>;
    onBack: () => void;
  } = $props();

  let displayName = $state('');
  let password = $state('');
  let confirm = $state('');

  const match = $derived(passwordsMatch(password, confirm));
  const showMismatch = $derived(confirm.length > 0 && password !== confirm);
  const canCreate = $derived(!submitting && displayName.trim().length > 0 && match);

  function submit(): void {
    if (!canCreate) return;
    onCreate(displayName.trim(), password);
    password = '';
    confirm = '';
  }
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Set a password</h2>
  <p class="wizard-step__hint">Creating a vault in {folder}.</p>

  <label class="wizard-step__field" for="credentials-display-name">
    <span>Display name</span>
    <input
      id="credentials-display-name"
      type="text"
      bind:value={displayName}
      placeholder="Your name"
      disabled={submitting}
    />
  </label>

  <label class="wizard-step__field" for="credentials-password">
    <span>Password</span>
    <input
      id="credentials-password"
      type="password"
      bind:value={password}
      placeholder="••••••••"
      disabled={submitting}
    />
  </label>

  <label class="wizard-step__field" for="credentials-confirm">
    <span>Confirm password</span>
    <input
      id="credentials-confirm"
      type="password"
      bind:value={confirm}
      placeholder="••••••••"
      disabled={submitting}
    />
  </label>

  {#if showMismatch}
    <p class="wizard-step__warn">Passwords don't match.</p>
  {/if}

  <p class="wizard-step__hint">
    There is no password reset — your recovery phrase (shown next) is the only way back in.
  </p>

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__cancel" onclick={onBack} disabled={submitting}>Back</button>
    <button type="button" class="wizard-step__next" disabled={!canCreate} onclick={submit}>
      {submitting ? 'Creating…' : 'Create vault'}
    </button>
  </div>
</div>
