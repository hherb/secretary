<script lang="ts">
  import type { BlockSummaryDto, RecordDto, RecordRefDto } from '../../lib/ipc';
  import { saveRecord, saveRecordEdit, revealRecord } from '../../lib/ipc';
  import {
    emptyDraft, emptyField, recordToDraft, validateRecordDraft, draftToRecordInputDto,
    type RecordDraft, type EditorFieldDraft
  } from '../../lib/editor';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import FieldRowEditor from './FieldRowEditor.svelte';
  import TagsEditor from './TagsEditor.svelte';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';

  // record === null → add mode; otherwise edit mode (prefilled via revealRecord).
  let { block, record, onSaved, onCancel }: {
    block: BlockSummaryDto;
    record: RecordDto | null;
    onSaved: (ref: RecordRefDto) => void;
    onCancel: () => void;
  } = $props();

  let draft = $state<RecordDraft>(emptyDraft());
  let submitting = $state(false);
  // `record` is captured ONCE at mount (the parent re-mounts RecordEditor per
  // edit session), so seeding `loading` from it is intentional — it keeps
  // loading=true from the very first render in edit mode and avoids a flash of
  // the empty form before revealRecord resolves. The svelte-check
  // state_referenced_locally note here is expected and intentional.
  // svelte-ignore state_referenced_locally
  let loading = $state(record !== null);
  let errMsg = $state<ReturnType<typeof userMessageFor> | null>(null);

  // Edit mode: reveal the one record's fields for prefill (siblings untouched).
  $effect(() => {
    if (record === null) return;
    let cancelled = false;
    revealRecord(block.blockUuidHex, record.recordUuidHex)
      .then((reveal) => { if (!cancelled) { draft = recordToDraft(record, reveal); loading = false; } })
      .catch((e) => { if (!cancelled) { errMsg = userMessageFor(e as AppError); loading = false; } });
    return () => { cancelled = true; };
  });

  const validation = $derived(validateRecordDraft(draft));
  const canSave = $derived(!submitting && !loading && draft.fields.length > 0 && validation.ok);

  function addField(): void { draft = { ...draft, fields: [...draft.fields, emptyField()] }; }
  function setField(i: number, f: EditorFieldDraft): void {
    draft = { ...draft, fields: draft.fields.map((x, j) => (j === i ? f : x)) };
  }
  function removeField(i: number): void {
    draft = { ...draft, fields: draft.fields.filter((_, j) => j !== i) };
  }

  async function save(): Promise<void> {
    if (!canSave) return;
    submitting = true; errMsg = null;
    const reason = record === null ? 'Confirm saving this entry' : 'Confirm saving your changes';
    try {
      await authorizeWrite(reason);
    } catch (err) {
      if (err === ReauthCancelled) { submitting = false; return; }
      errMsg = userMessageFor(err as AppError);
      submitting = false;
      return;
    }
    const dto = draftToRecordInputDto(draft);
    try {
      const ref = record === null
        ? await saveRecord(block.blockUuidHex, dto)
        : await saveRecordEdit(block.blockUuidHex, record.recordUuidHex, dto);
      // Clear secret-bearing draft values right after a successful save.
      draft = emptyDraft();
      onSaved(ref);
    } catch (err) {
      errMsg = userMessageFor(err as AppError);
    } finally {
      submitting = false;
    }
  }

  // Cancel symmetrically clears the secret-bearing draft before navigating
  // away — the unmount + GC would eventually drop it, but dropping the
  // references now mirrors the post-save clear (and the D.1.3 CredentialsStep
  // discipline) so a discarded draft's plaintext does not linger reachable.
  function cancel(): void {
    draft = emptyDraft();
    onCancel();
  }
</script>

<section class="editor">
  <button type="button" class="editor__back" onclick={cancel}>← Cancel</button>
  <h2 class="editor__title">{record === null ? 'Add record' : 'Edit record'}</h2>

  {#if errMsg}
    <div class="editor__error" role="alert">
      <div class="editor__error-title">{errMsg.title}</div>
      {#if errMsg.detail}<div class="editor__error-detail">{errMsg.detail}</div>{/if}
    </div>
  {/if}

  {#if loading}
    <p class="editor__loading">Loading…</p>
  {:else}
    <label class="editor__field" for="rec-type"><span>Type (optional)</span>
      <input id="rec-type" type="text" bind:value={draft.recordType} placeholder="e.g. login" />
    </label>

    <TagsEditor tags={draft.tags} onChange={(tags) => (draft = { ...draft, tags })} />

    <div class="editor__fields">
      {#each draft.fields as field, i (i)}
        <FieldRowEditor {field} error={validation.fieldErrors[i]} onChange={(f) => setField(i, f)} onRemove={() => removeField(i)} />
      {/each}
      <button type="button" class="editor__add-field" onclick={addField}>+ Add field</button>
    </div>

    <div class="editor__actions">
      <button type="button" disabled={!canSave} onclick={save}>{submitting ? 'Saving…' : 'Save'}</button>
    </div>
  {/if}
</section>
