<script module lang="ts">
  // Exported so it can be unit-tested directly (RepairConsentDialog.test.ts)
  // and so any future recipient-fingerprint display elsewhere can reuse the
  // same grouping without re-deriving it. Groups a hex string into
  // space-separated 4-char chunks for easier visual comparison, e.g.
  // "a1b2c3d4" -> "a1b2 c3d4". A trailing partial chunk (length not a
  // multiple of 4) is kept as-is rather than padded.
  export function groupHex(hex: string): string {
    const groups: string[] = [];
    for (let i = 0; i < hex.length; i += 4) {
      groups.push(hex.slice(i, i + 4));
    }
    return groups.join(' ');
  }
</script>

<script lang="ts">
  // #374 Task 10: informed-consent modal for the recipient widenings a
  // `previewRepair` call found. Mirrors delete/ConfirmDialog's shape (native
  // <dialog>, callback props, JSDOM showModal polyfill in tests/setup.ts) but
  // is not itself destructive — it is the gate that turns an otherwise
  // fail-closed repair into a user-approved one.
  //
  // Contract (pinned by RepairConsentDialog.test.ts):
  //   - showModal() on mount via $effect (the dialog only exists while a
  //     preview found at least one widening — see Unlock.svelte).
  //   - Cancel is the safe default and receives initial focus. JSDOM's
  //     showModal polyfill does not implement the browser's autofocus/
  //     dialog-focus-delegate step, so focus is set explicitly rather than
  //     relying solely on the `autofocus` attribute.
  //   - One Grant covers every listed widening; there are no per-block
  //     checkboxes — `onGrant` takes no arguments, and Unlock.svelte builds
  //     the approvals from the full `widenings` prop it already holds.
  //   - Copy is the spec's exact security copy (docs §7) — do not paraphrase.

  import type { WideningReportDto } from '../lib/ipc';

  type Props = {
    widenings: WideningReportDto[];
    onCancel: () => void;
    onGrant: () => void;
  };
  let { widenings, onCancel, onGrant }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  let cancelBtnEl: HTMLButtonElement | undefined = $state();

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  // Explicit focus (see contract note above) rather than relying on the
  // native autofocus-on-showModal behavior alone.
  $effect(() => {
    cancelBtnEl?.focus();
  });

  // Esc dismiss: same rationale as ConfirmDialog — prevent the native close
  // so the parent unmounting in response to onCancel is the single teardown
  // path.
  function onNativeCancel(event: Event) {
    event.preventDefault();
    onCancel();
  }
</script>

<dialog
  bind:this={dialogEl}
  class="repair-consent"
  aria-labelledby="repair-consent-title"
  oncancel={onNativeCancel}
>
  <h2 id="repair-consent-title" class="repair-consent__title">An interrupted share was found.</h2>
  <p class="repair-consent__body">
    Adopting this repair will give these contacts access to this block. If you don't recognize
    this, choose Cancel — the vault stays unchanged.
  </p>

  <div class="repair-consent__blocks">
    {#each widenings as widening (widening.blockUuidHex)}
      <div class="repair-consent__block">
        <div class="repair-consent__block-name">{widening.blockName}</div>
        <ul class="repair-consent__recipients">
          {#each widening.added as recipient (recipient.uuidHex)}
            <li class="repair-consent__recipient">
              <span class="repair-consent__recipient-name">{recipient.displayName}</span>
              <span class="repair-consent__recipient-fingerprint"
                >{groupHex(recipient.cardFingerprintHex)}</span
              >
            </li>
          {/each}
        </ul>
      </div>
    {/each}
  </div>

  <div class="repair-consent__actions">
    <!-- svelte-ignore a11y_autofocus -->
    <button
      type="button"
      class="repair-consent__button"
      bind:this={cancelBtnEl}
      autofocus
      onclick={onCancel}
    >
      Cancel
    </button>
    <button
      type="button"
      class="repair-consent__button repair-consent__button--primary"
      onclick={onGrant}
    >
      Grant access and repair
    </button>
  </div>
</dialog>
