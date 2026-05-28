<script lang="ts">
  import { get } from 'svelte/store';
  import { lock } from '../lib/ipc';
  import { sessionState, beginLock, lockFailed } from '../lib/stores';
  import type { AppError } from '../lib/errors';

  async function handleClick() {
    // Defensive — Vault only mounts us when status === 'unlocked' but
    // a fast double-click can sneak in between transition and unmount.
    if (get(sessionState).status !== 'unlocked') return;

    beginLock();
    try {
      await lock();
      // Intentionally no transition here. The App.svelte `vault-locked`
      // event listener calls `vaultLocked()` when the backend confirms.
      // Frontend mirrors backend reality per spec §7.
    } catch (e) {
      lockFailed(e as AppError);
    }
  }
</script>

<button type="button" class="lock-button" onclick={handleClick}>
  🔒 Lock
</button>
