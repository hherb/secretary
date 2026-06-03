<script lang="ts">
  import { open as openDialog } from '@tauri-apps/plugin-dialog';

  // A single file filter (name + allowed extensions) as accepted by the
  // Tauri dialog plugin. Mirrors `DialogFilter` without importing the
  // plugin's type so this stays a thin, stable contract.
  type PickerFilter = { name: string; extensions: string[] };

  // `directory`, `filters`, `title`, and `label` are optional so existing
  // folder-mode call sites (vault create / unlock) keep their behaviour:
  // `directory` defaults to true (folder selection), `filters` is unused in
  // folder mode, the dialog title falls back to the folder prompt, and the
  // button keeps its "Choose…" label. File-mode callers (contact-card import)
  // pass `directory={false}` plus `filters`/`title`/`label`.
  type Props = {
    value: string;
    onSelect: (path: string) => void;
    disabled?: boolean;
    directory?: boolean;
    filters?: PickerFilter[];
    title?: string;
    label?: string;
  };

  const DEFAULT_FOLDER_TITLE = 'Choose vault folder';

  let {
    value,
    onSelect,
    disabled = false,
    directory = true,
    filters,
    title,
    label = 'Choose…'
  }: Props = $props();

  async function pick(): Promise<void> {
    // Disabled buttons can't be clicked via the UI, but a stray
    // programmatic dispatch shouldn't leak a stray dialog.
    if (disabled) return;
    const selected = await openDialog({
      directory,
      multiple: false,
      title: title ?? (directory ? DEFAULT_FOLDER_TITLE : undefined),
      // `filters` only applies to file selection; passing it in folder mode
      // is harmless (the plugin ignores it) but we keep it undefined there.
      filters: directory ? undefined : filters
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
    placeholder={directory ? 'No folder selected' : 'No file selected'}
    {disabled}
  />
  <button type="button" onclick={pick} {disabled}>{label}</button>
</div>
