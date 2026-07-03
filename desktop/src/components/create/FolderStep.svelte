<script lang="ts">
  import PathPicker from '../PathPicker.svelte';
  import { probeCreateTarget } from '../../lib/ipc';
  import { joinSubfolder } from '../../lib/create';

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

  let probeGeneration = 0;

  async function probe(path: string): Promise<void> {
    if (path.length === 0) {
      probed = null;
      return;
    }
    const gen = ++probeGeneration;
    probing = true;
    try {
      const result = await probeCreateTarget(path);
      if (gen === probeGeneration) {
        probed = result;
      }
    } finally {
      if (gen === probeGeneration) {
        probing = false;
      }
    }
  }

  $effect(() => {
    void probe(picked);
  });

  const needsSubfolder = $derived(probed !== null && probed.exists && !probed.isEmpty);

  const finalPath = $derived(
    needsSubfolder ? joinSubfolder(picked, subfolderName) : picked.length > 0 ? picked : null
  );

  const canContinue = $derived(!probing && finalPath !== null);

  function onPick(p: string): void {
    picked = p;
    subfolderName = '';
  }
</script>

<div class="wizard-step">
  <h2 class="wizard-step__title">Choose a folder</h2>
  <p class="wizard-step__hint">Pick an empty folder, or a folder to create your vault inside.</p>

  <PathPicker value={picked} command="pick_vault_folder" onSelect={onPick} disabled={probing} />

  {#if needsSubfolder}
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
