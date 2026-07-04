<script lang="ts">
  import PathPicker from '../PathPicker.svelte';
  import { probeCreateTarget } from '../../lib/ipc';
  import { joinSubfolder } from '../../lib/create';
  import { userMessageFor, type AppError } from '../../lib/errors';

  let {
    seedPath = '',
    onNext,
    onCancel
  }: { seedPath?: string; onNext: (folder: string) => void; onCancel: () => void } = $props();

  // seedPath is read ONCE to seed the picker; thereafter `picked` is
  // user-driven. The svelte-check `state_referenced_locally` note is expected
  // and intentional — the seed is deliberately not reactive after mount.
  // svelte-ignore state_referenced_locally
  let picked = $state(seedPath);
  let probed = $state<{ exists: boolean; isEmpty: boolean } | null>(null);
  let subfolderName = $state('');
  let probing = $state(false);
  // #378: create has its own approval slot (CreateParent), populated only by
  // the pick_create_folder dialog. A seed path carried over from the Unlock
  // screen is NOT approved for creation, so probing it rejects with
  // path_not_approved — the user must confirm the folder via the picker.
  let needsPick = $state(false);
  // A non-approval probe failure (io, internal, …). Surfaced inline so the
  // step never dead-ends silently with Continue disabled and no explanation.
  let probeError = $state<string | null>(null);

  let probeGeneration = 0;

  async function probe(path: string): Promise<void> {
    const gen = ++probeGeneration;
    // Clear the previous verdict up front so a slow probe never leaves the
    // prior folder's "Ready to create"/subfolder guidance on screen while the
    // new path is still being checked.
    probed = null;
    needsPick = false;
    probeError = null;
    if (path.length === 0) {
      probing = false;
      return;
    }
    probing = true;
    try {
      const result = await probeCreateTarget(path);
      if (gen === probeGeneration) {
        probed = result;
      }
    } catch (err) {
      if (gen === probeGeneration) {
        const code = (err as Partial<AppError>).code;
        if (code === 'path_not_approved') {
          needsPick = true;
        } else {
          // io/internal/etc: show a concrete reason instead of a silent
          // greyed-out Continue with no explanation.
          probeError = userMessageFor(err as AppError).title;
        }
      }
    } finally {
      if (gen === probeGeneration) {
        probing = false;
      }
    }
  }

  // Probe the seed once on mount (a carried-over Unlock path is not approved
  // for creation, so this surfaces `needsPick`). Every subsequent pick
  // re-probes explicitly in `onPick` rather than through a `picked`-tracking
  // effect: re-picking the SAME folder as the rejected seed yields an
  // identical string, and Svelte skips the reactive update on an unchanged
  // primitive, so an effect would never re-fire — stranding the step with
  // Continue disabled even though `pick_create_folder` just approved the
  // path (#378).
  $effect(() => {
    void probe(seedPath);
  });

  const needsSubfolder = $derived(probed !== null && probed.exists && !probed.isEmpty);

  const finalPath = $derived(
    needsSubfolder ? joinSubfolder(picked, subfolderName) : picked.length > 0 ? picked : null
  );

  // A successful probe (probed !== null) is required: it proves the backend
  // holds a CreateParent approval covering `picked`, so create_vault won't
  // bounce with path_not_approved after the credentials step.
  const canContinue = $derived(!probing && probed !== null && finalPath !== null);

  function onPick(p: string): void {
    picked = p;
    subfolderName = '';
    // Re-probe explicitly. We can't rely on `picked` changing to drive this:
    // re-picking the same folder as the rejected seed is a no-op for Svelte
    // reactivity, but it must still re-probe now that `pick_create_folder`
    // has approved the path (see the mount effect's note).
    void probe(p);
  }
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Choose a folder</h2>
  <p class="wizard-step__hint">Pick an empty folder, or a folder to create your vault inside.</p>

  <PathPicker value={picked} command="pick_create_folder" onSelect={onPick} disabled={probing} />

  {#if needsPick}
    <p class="wizard-step__warn">Confirm the folder with the Choose… button to continue.</p>
  {:else if probeError}
    <p class="wizard-step__warn">{probeError}</p>
  {:else if needsSubfolder}
    <p class="wizard-step__warn">{picked} already contains files.</p>
    <label class="wizard-step__field" for="subfolder-name">
      <span>Subfolder name</span>
      <input id="subfolder-name" type="text" bind:value={subfolderName} placeholder="my-vault" />
    </label>
    {#if finalPath}
      <p class="wizard-step__hint">Will create: {finalPath}</p>
    {/if}
  {:else if probed && picked.length > 0}
    <p class="wizard-step__hint">Ready to create in {picked}</p>
  {/if}

  <div class="wizard-step__actions">
    <button type="button" class="wizard-step__cancel" onclick={onCancel}>Cancel</button>
    <button
      type="button"
      class="wizard-step__next"
      disabled={!canContinue}
      onclick={() => finalPath && onNext(finalPath)}
    >
      Continue
    </button>
  </div>
</div>
