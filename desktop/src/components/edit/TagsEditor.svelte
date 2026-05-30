<script lang="ts">
  let { tags, onChange }: { tags: string[]; onChange: (tags: string[]) => void } = $props();
  let draft = $state('');

  function add(): void {
    const t = draft.trim();
    if (t.length === 0 || tags.includes(t)) { draft = ''; return; }
    onChange([...tags, t]);
    draft = '';
  }
  function remove(tag: string): void {
    onChange(tags.filter((t) => t !== tag));
  }
</script>

<div class="tags-editor">
  {#each tags as tag (tag)}
    <span class="tags-editor__chip">{tag}
      <button type="button" aria-label={`remove tag ${tag}`} onclick={() => remove(tag)}>×</button>
    </span>
  {/each}
  <label class="tags-editor__add" for="tags-editor-input">
    <span class="visually-hidden">Add tag</span>
    <input id="tags-editor-input" type="text" bind:value={draft} placeholder="tag name" />
  </label>
  <button type="button" onclick={add}><span class="visually-hidden">Add tag</span><span aria-hidden="true">Add</span></button>
</div>
