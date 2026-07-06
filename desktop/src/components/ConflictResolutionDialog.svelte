<script lang="ts">
  // Interactive sync-conflict resolver (Task 12). Native <dialog> mirroring
  // SyncPasswordDialog: callback props, showModal() on mount via $effect,
  // Esc → preventDefault + onCancel so the parent's unmount is the single
  // close route. One card per veto (metadata only — no secret values cross
  // the IPC boundary) with a Keep-mine / Accept-delete toggle defaulting to
  // Keep mine (the no-data-loss safe choice). Auto-merged field collisions
  // are surfaced read-only for disclosure, not as a prompt. The mutation is
  // strict: a failure renders the typed AppError inline and keeps the dialog
  // open for a retry; onResolved fires only on success. The password is a
  // prop (held by the parent) — never prompted, logged, or stashed here.
  import { syncCommitDecisions, isAppError } from '../lib/ipc';
  import { userMessageFor, type AppError } from '../lib/errors';
  import {
    collectDecisions,
    decisionsComplete,
    formatVetoSummary,
    type VetoDto,
    type CollisionDto,
    type SyncOutcome,
    type VetoChoices
  } from '../lib/sync';

  type Props = {
    vetoes: VetoDto[];
    collisions: CollisionDto[];
    manifestHash: number[];
    password: string;
    onResolved: (outcome: SyncOutcome) => void;
    onCancel: () => void;
  };
  let { vetoes, collisions, manifestHash, password, onResolved, onCancel }: Props = $props();

  let dialogEl: HTMLDialogElement | undefined = $state();
  // Explicit per-veto overrides. Empty initially; an unset record reads as
  // Keep mine (true) via `effectiveChoices` below — defaulting to the
  // no-data-loss choice without seeding from a prop (which would only ever
  // capture the prop's initial value here).
  let overrides = $state<VetoChoices>({});
  let busy = $state(false);
  let error = $state<AppError | null>(null);

  // Resolve every veto to a concrete boolean: an explicit override if the
  // user toggled it, otherwise the Keep-mine (true) default.
  const effectiveChoices = $derived<VetoChoices>(
    Object.fromEntries(vetoes.map((v) => [v.recordUuidHex, overrides[v.recordUuidHex] ?? true]))
  );

  const canApply = $derived(!busy && decisionsComplete(vetoes, effectiveChoices));

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) {
      dialogEl.showModal();
    }
  });

  function setChoice(id: string, keepLocal: boolean) {
    overrides = { ...overrides, [id]: keepLocal };
  }

  function onNativeCancel(event: Event) {
    event.preventDefault();
    onCancel();
  }

  async function apply(event: Event) {
    event.preventDefault();
    if (!canApply) return;
    busy = true;
    error = null;
    try {
      const outcome = await syncCommitDecisions(
        password,
        collectDecisions(vetoes, effectiveChoices),
        manifestHash
      );
      onResolved(outcome);
    } catch (err) {
      error = isAppError(err) ? err : { code: 'internal' };
    } finally {
      busy = false;
    }
  }
</script>

<dialog
  bind:this={dialogEl}
  class="conflict-dialog"
  aria-labelledby="conflict-dialog-title"
  oncancel={onNativeCancel}
>
  <form class="conflict-dialog__form" onsubmit={apply}>
    <h2 id="conflict-dialog-title" class="conflict-dialog__title">Resolve sync conflicts</h2>
    <p class="conflict-dialog__subtitle">
      These records were deleted on another device but you still have them. Choose what to keep —
      nothing is written until you click Apply.
    </p>

    <ul class="conflict-dialog__list">
      {#each vetoes as v (v.recordUuidHex)}
        <li class="conflict-dialog__card">
          <div class="conflict-dialog__meta">
            <strong class="conflict-dialog__summary">{formatVetoSummary(v)}</strong>
            <span class="conflict-dialog__fields">fields: {v.fieldNames.join(' · ')}</span>
            <span class="conflict-dialog__device">deleted on device {v.peerDeviceHex.slice(0, 4)}…</span>
          </div>
          <div
            class="conflict-dialog__choices"
            role="group"
            aria-label={`Resolution for ${formatVetoSummary(v)}`}
          >
            <button
              type="button"
              class="conflict-dialog__toggle"
              class:conflict-dialog__toggle--active={effectiveChoices[v.recordUuidHex] === true}
              aria-pressed={effectiveChoices[v.recordUuidHex] === true}
              onclick={() => setChoice(v.recordUuidHex, true)}
              disabled={busy}
            >
              Keep mine
            </button>
            <button
              type="button"
              class="conflict-dialog__toggle"
              class:conflict-dialog__toggle--active={effectiveChoices[v.recordUuidHex] === false}
              aria-pressed={effectiveChoices[v.recordUuidHex] === false}
              onclick={() => setChoice(v.recordUuidHex, false)}
              disabled={busy}
            >
              Accept delete
            </button>
          </div>
        </li>
      {/each}
    </ul>

    {#if collisions.length > 0}
      <details class="conflict-dialog__collisions">
        <summary class="conflict-dialog__collisions-summary">
          {collisions.length} field(s) auto-merged (newer edit won) — no action needed
        </summary>
        <ul class="conflict-dialog__collisions-list">
          {#each collisions as c (c.recordUuidHex)}
            <li>{c.fieldNames.join(', ')}</li>
          {/each}
        </ul>
      </details>
    {/if}

    {#if error}
      {@const msg = userMessageFor(error)}
      <p class="conflict-dialog__error" role="alert">
        {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
      </p>
    {/if}

    <div class="conflict-dialog__actions">
      <button type="button" class="conflict-dialog__button" onclick={onCancel} disabled={busy}>
        Cancel
      </button>
      <button
        type="submit"
        class="conflict-dialog__button conflict-dialog__button--primary"
        disabled={!canApply}
      >
        {busy ? 'Applying…' : 'Apply & finish sync'}
      </button>
    </div>
  </form>
</dialog>
