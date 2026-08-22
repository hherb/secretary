<script lang="ts">
  import LockButton from './LockButton.svelte';
  import Settings from './icons/Settings.svelte';
  import SyncPill from './SyncPill.svelte';
  import BrandMark from './BrandMark.svelte';

  type Props = {
    vaultLabel: string;
    onOpenSettings: () => void;
  };
  let { vaultLabel, onOpenSettings }: Props = $props();
</script>

<header class="top-bar">
  <div class="top-bar__left">
    <span class="top-bar__brand" aria-hidden="true"><BrandMark size={32} /></span>
    <span class="top-bar__identity">
      <strong class="top-bar__title">Secretary</strong>
      <span class="top-bar__vault-label">
        <span class="top-bar__vault-prefix">Vault</span>
        <span>{vaultLabel}</span>
      </span>
    </span>
  </div>
  <div class="top-bar__right">
    <SyncPill />
    <button
      type="button"
      class="top-bar__settings"
      onclick={onOpenSettings}
      title="Settings"
      aria-label="Settings"
    >
      <Settings /><span class="top-bar__control-label">Settings</span>
    </button>
    <LockButton />
  </div>
</header>
