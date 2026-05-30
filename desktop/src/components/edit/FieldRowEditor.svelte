<script lang="ts">
  import type { EditorFieldDraft, FieldKind } from '../../lib/editor';
  let {
    field, error, onChange, onRemove
  }: {
    field: EditorFieldDraft;
    error?: string;
    onChange: (f: EditorFieldDraft) => void;
    onRemove: () => void;
  } = $props();

  function patch(p: Partial<EditorFieldDraft>): void {
    onChange({ ...field, ...p });
  }
</script>

<div class="field-row-editor">
  <input
    type="text" aria-label="field name" placeholder="name"
    value={field.name} oninput={(e) => patch({ name: e.currentTarget.value })}
  />
  <select aria-label="field type" value={field.kind} onchange={(e) => patch({ kind: e.currentTarget.value as FieldKind })}>
    <option value="text">text</option>
    <option value="bytes">bytes (base64)</option>
  </select>
  <input
    type="text" aria-label="field value"
    placeholder={field.kind === 'bytes' ? 'base64' : 'value'}
    value={field.value} oninput={(e) => patch({ value: e.currentTarget.value })}
  />
  <button type="button" aria-label="remove field" onclick={onRemove}>×</button>
  {#if error}<span class="field-row-editor__error" role="alert">{error}</span>{/if}
</div>
