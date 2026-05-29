<script lang="ts">
  import FolderStep from '../components/create/FolderStep.svelte';
  import CredentialsStep from '../components/create/CredentialsStep.svelte';
  import MnemonicStep from '../components/create/MnemonicStep.svelte';
  import { startWizard, toCredentials, toMnemonic, type WizardStep } from '../lib/create';
  import { createVault } from '../lib/ipc';
  import { userMessageFor } from '../lib/errors';
  import { createSeedPath, cancelCreateWizard, finishCreateWizard } from '../lib/route';
  import { get } from 'svelte/store';
  import type { AppError } from '../lib/errors';

  let wizardState = $state<WizardStep>(startWizard());
  let submitting = $state(false);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);
  const seed = get(createSeedPath);

  function gotoCredentials(folder: string): void {
    errMsg = null;
    wizardState = toCredentials(folder);
  }

  async function create(displayName: string, password: string): Promise<void> {
    if (wizardState.step !== 'credentials' || submitting) return;
    submitting = true;
    errMsg = null;
    const folder = wizardState.folder;
    try {
      const dto = await createVault(folder, displayName, password);
      wizardState = toMnemonic(folder, dto.mnemonic);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }

  function done(): void {
    if (wizardState.step === 'mnemonic') {
      finishCreateWizard(wizardState.folder);
    }
  }
</script>

<main class="wizard">
  <div class="wizard__card">
    <h1 class="wizard__title">Create a vault</h1>

    {#if errMsg}
      <div class="wizard__error" role="alert">
        <div class="wizard__error-title">{errMsg.title}</div>
        {#if errMsg.detail}<div class="wizard__error-detail">{errMsg.detail}</div>{/if}
        {#if errMsg.actionHint}<div class="wizard__error-hint">{errMsg.actionHint}</div>{/if}
      </div>
    {/if}

    {#if wizardState.step === 'folder'}
      <FolderStep seedPath={seed} onNext={gotoCredentials} onCancel={cancelCreateWizard} />
    {:else if wizardState.step === 'credentials'}
      <CredentialsStep
        folder={wizardState.folder}
        {submitting}
        onCreate={create}
        onBack={() => (wizardState = startWizard())}
      />
    {:else}
      <MnemonicStep mnemonic={wizardState.mnemonic} onDone={done} />
    {/if}
  </div>
</main>
