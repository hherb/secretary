<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';

  // #353: the picker no longer opens a dialog in the webview. It invokes a
  // backend `pick_*` command, which opens the native dialog, records the
  // chosen path in Rust state, and returns it for display. `command` selects
  // which purpose to pick for.
  type Props = {
    value: string;
    onSelect: (path: string) => void;
    command: 'pick_vault_folder' | 'pick_create_folder' | 'pick_contact_card' | 'pick_export_dir';
    disabled?: boolean;
    label?: string;
    placeholder?: string;
  };

  let {
    value,
    onSelect,
    command,
    disabled = false,
    label = 'Choose…',
    placeholder = 'No path selected'
  }: Props = $props();

  async function pick(): Promise<void> {
    if (disabled) return;
    const selected = await invoke<string | null>(command);
    if (typeof selected === 'string') {
      onSelect(selected);
    }
  }
</script>

<!-- Styles live in `src/theme.css` as `.path-picker { … }`. -->
<div class="path-picker">
  <input type="text" readonly value={value || ''} {placeholder} {disabled} />
  <button type="button" onclick={pick} {disabled}>{label}</button>
</div>
