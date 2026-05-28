<script lang="ts">
  import LockButton from './LockButton.svelte';

  type Props = {
    vaultLabel: string;
    onOpenSettings: () => void;
  };
  let { vaultLabel, onOpenSettings }: Props = $props();
</script>

<header class="top-bar">
  <div class="top-bar__left">
    <strong class="top-bar__title">Secretary</strong>
    <span class="top-bar__vault-label">{vaultLabel}</span>
  </div>
  <div class="top-bar__right">
    <button
      type="button"
      class="top-bar__settings"
      onclick={onOpenSettings}
      title="Settings"
      aria-label="Settings"
    >
      ⚙️ Settings
    </button>
    <LockButton />
  </div>
</header>
