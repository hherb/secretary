<script lang="ts">
  import { open as openDialog } from '@tauri-apps/plugin-dialog';

  type Props = {
    value: string;
    onSelect: (path: string) => void;
    disabled?: boolean;
  };

  const PICKER_TITLE = 'Choose vault folder';

  let { value, onSelect, disabled = false }: Props = $props();

  async function pick(): Promise<void> {
    // Disabled buttons can't be clicked via the UI, but a stray
    // programmatic dispatch shouldn't leak a stray dialog.
    if (disabled) return;
    const selected = await openDialog({
      directory: true,
      multiple: false,
      title: PICKER_TITLE
    });
    // `multiple: false` constrains the return to `string | null`, but
    // we defend against a future refactor that flips `multiple: true`
    // by ignoring array returns rather than passing them through.
    if (typeof selected === 'string') {
      onSelect(selected);
    }
  }
</script>

<!-- Styles live in `src/theme.css` as `.path-picker { … }`; see the note
     at the bottom of theme.css for why component-scoped `<style>` blocks
     are avoided in this project. -->
<div class="path-picker">
  <input
    type="text"
    readonly
    value={value || ''}
    placeholder="No folder selected"
    {disabled}
  />
  <button type="button" onclick={pick} {disabled}>Choose…</button>
</div>
