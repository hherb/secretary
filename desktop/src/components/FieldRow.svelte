<script lang="ts">
  import Eye from './icons/Eye.svelte';
  import EyeOff from './icons/EyeOff.svelte';
  import { writeText } from '@tauri-apps/plugin-clipboard-manager';
  import { revealField, isAppError, type FieldMetaDto } from '../lib/ipc';
  import { createAutoHideTimer } from '../lib/reveal';
  import { REVEAL_AUTO_HIDE_MS, CLIPBOARD_CLEAR_MS } from '../lib/constants';

  type Props = { blockUuidHex: string; recordUuidHex: string; field: FieldMetaDto };
  let { blockUuidHex, recordUuidHex, field }: Props = $props();

  let revealed = $state<string | null>(null);
  let isTextValue = $state(true);
  let busy = $state(false);
  let failed = $state(false);
  let copyFailed = $state(false);

  const hideTimer = createAutoHideTimer(() => mask(), REVEAL_AUTO_HIDE_MS);

  async function reveal(): Promise<void> {
    if (busy) return;
    busy = true; failed = false;
    try {
      const dto = await revealField(blockUuidHex, recordUuidHex, field.name);
      revealed = dto.value;
      isTextValue = dto.isText;
      hideTimer.start();
    } catch (e) {
      failed = true;
      if (!isAppError(e)) console.error('reveal_field failed', e);
    } finally {
      busy = false;
    }
  }

  function mask(): void {
    revealed = null;
    copyFailed = false;
    hideTimer.cancel();
  }

  let clipboardClearHandle: ReturnType<typeof setTimeout> | null = null;

  function clearClipboardClear(): void {
    if (clipboardClearHandle !== null) {
      clearTimeout(clipboardClearHandle);
      clipboardClearHandle = null;
    }
  }

  async function copy(): Promise<void> {
    if (revealed === null) return;
    const value = revealed;
    copyFailed = false;
    try {
      await writeText(value);
    } catch (e) {
      // The plugin write can fail (OS clipboard busy / permission). Surface
      // it inline rather than swallowing into an unhandled rejection, and
      // do NOT schedule a clear — nothing was written.
      copyFailed = true;
      console.error('clipboard write failed', e);
      return;
    }
    // Best-effort clear, reset on each copy so the full window applies to the
    // most recent copy (spec §8: may still clobber newer external clipboard
    // content — that tradeoff is accepted).
    clearClipboardClear();
    clipboardClearHandle = setTimeout(() => {
      clipboardClearHandle = null;
      void writeText('');
    }, CLIPBOARD_CLEAR_MS);
  }

  // On unmount (navigate away or vault lock — both unmount this subtree),
  // tear down timers. The auto-hide timer just re-masks, so cancelling it is
  // enough. But a *pending clipboard clear* must not simply be cancelled:
  // doing so would strand the copied plaintext in the OS clipboard past the
  // lock, violating spec §7 ("revealed secrets must not survive a lock").
  // The OS clipboard is cross-process state independent of this component, so
  // we fire the clear NOW instead of dropping it.
  $effect(() => () => {
    hideTimer.cancel();
    if (clipboardClearHandle !== null) {
      clearClipboardClear();
      void writeText('');
    }
  });
</script>

<div class="field-row">
  <span class="field-row__name">{field.name}</span>

  {#if revealed === null}
    <span class="field-row__masked">{field.isBytes ? 'binary' : '••••••••'}</span>
    <button type="button" class="field-row__btn" aria-label={`reveal ${field.name}`} onclick={reveal} disabled={busy}><Eye /></button>
  {:else}
    <code class="field-row__value">{revealed}{isTextValue ? '' : ' (base64)'}</code>
    <button type="button" class="field-row__btn" aria-label={`hide ${field.name}`} onclick={mask}><EyeOff /></button>
    <button type="button" class="field-row__btn" aria-label={`copy ${field.name}`} onclick={copy}>⧉</button>
  {/if}

  {#if failed}<span class="field-row__error" role="alert">Couldn't reveal.</span>{/if}
  {#if copyFailed}<span class="field-row__error" role="alert">Couldn't copy.</span>{/if}
</div>
