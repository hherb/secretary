<script lang="ts">
  import { onDestroy } from 'svelte';
  import { writeText } from '@tauri-apps/plugin-clipboard-manager';
  import { groupMnemonicWords } from '../../lib/create';
  import { CLIPBOARD_CLEAR_MS } from '../../lib/constants';

  let { mnemonic, onDone }: { mnemonic: string; onDone: () => void } = $props();

  let acknowledged = $state(false);
  let copied = $state(false);
  const words = $derived(groupMnemonicWords(mnemonic));

  let clearTimer: ReturnType<typeof setTimeout> | null = null;

  async function copy(): Promise<void> {
    await writeText(mnemonic);
    copied = true;
    if (clearTimer) clearTimeout(clearTimer);
    clearTimer = setTimeout(() => {
      void writeText('');
      copied = false;
    }, CLIPBOARD_CLEAR_MS);
  }

  // A pending clipboard clear must not simply be cancelled on unmount —
  // doing so would strand the copied recovery phrase in the OS clipboard
  // past the wizard's lifetime. The OS clipboard is cross-process state
  // independent of this component, so fire the clear now. Mirrors the
  // FieldRow.svelte precedent (D.1.2). If nothing was copied (no pending
  // timer), leave the clipboard untouched.
  onDestroy(() => {
    if (clearTimer) {
      clearTimeout(clearTimer);
      void writeText('');
    }
  });
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Your recovery phrase</h2>
  <p class="wizard-step__warn">
    Write these 24 words down and keep them safe. This is the ONLY way to recover your vault if you
    forget your password.
  </p>

  <ol class="mnemonic-grid">
    {#each words as w (w.index)}
      <li class="mnemonic-grid__item" data-testid="mnemonic-word">
        <span class="mnemonic-grid__index">{w.index}</span>
        <span class="mnemonic-grid__word">{w.word}</span>
      </li>
    {/each}
  </ol>

  <button type="button" class="wizard-step__copy" onclick={copy}>
    {copied ? 'Copied ✓' : 'Copy'}
  </button>

  <label class="wizard-step__ack" for="mnemonic-acknowledged">
    <input id="mnemonic-acknowledged" type="checkbox" bind:checked={acknowledged} />
    <span>I have written down my recovery phrase</span>
  </label>

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__next" disabled={!acknowledged} onclick={onDone}>
      Continue
    </button>
  </div>
</div>
