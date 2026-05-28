<script lang="ts">
  import { onMount } from 'svelte';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import { sessionState, autoLockNotice, vaultLocked } from './lib/stores';
  import { startActivityTracking } from './lib/auto_lock';
  import Unlock from './routes/Unlock.svelte';
  import Vault from './routes/Vault.svelte';
  import Toast from './components/Toast.svelte';
  import './theme.css';

  // The backend `vault-locked` event fires from two call sites:
  //   - explicit user-lock (`commands::lock`) → reason: 'explicit'
  //   - auto-lock timer tick (`main::auto_lock_timer_loop`) → reason: 'auto'
  // Both mean the same thing to the UI ("vault is now locked"); they
  // differ only in which AutoLockNotice copy the toast surface renders.
  type VaultLockedPayload = { reason: 'explicit' | 'auto' };

  // Map the backend reason to the AutoLockNotice reason. The shape pin
  // `vault_locked_event_name_is_kebab_case` on the Rust side keeps the
  // event name in lockstep with the listener string below.
  const REASON_TO_NOTICE = {
    explicit: 'manual',
    auto: 'idle'
  } as const;

  // Listener installation is async — `listen()` returns a Promise.
  // Stash the unlisten fn in a closure-local so the onMount cleanup
  // can detach even if the resolver lands after unmount.
  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    let unmounted = false;

    listen<VaultLockedPayload>('vault-locked', (event) => {
      const notice = REASON_TO_NOTICE[event.payload.reason];
      vaultLocked(notice);
    }).then((fn) => {
      if (unmounted) {
        // Unmount raced the listener resolve — detach immediately so we
        // don't leak the subscription across the component lifecycle.
        fn();
      } else {
        unlisten = fn;
      }
    });

    return () => {
      unmounted = true;
      if (unlisten) {
        unlisten();
      }
    };
  });

  // Activity tracking lifecycle. We only attach the document-level
  // listeners while the vault is unlocked — outside that window the
  // IPC keep-alive would be a no-op anyway (notify_activity is a silent
  // no-op when locked, see commands::lock::notify_activity_impl).
  // Tearing down on lock also prevents a small (but real) IPC-mutex
  // contention against the auto-lock timer tick.
  //
  // The `$derived` wrapping `$sessionState.status` is load-bearing:
  // it dedupes via === so a settingsUpdated transition (unlocked →
  // unlocked with new settings; same status string) does not re-fire
  // the effect, avoiding a tear-down-and-re-install of the document
  // listeners on every settings save. Without this, the effect would
  // re-run on every change to the whole sessionState signal.
  const sessionStatus = $derived($sessionState.status);

  $effect(() => {
    if (sessionStatus !== 'unlocked') {
      return;
    }
    return startActivityTracking();
  });
</script>

{#if $sessionState.status === 'unlocked'}
  <Vault />
{:else if $sessionState.status === 'locking'}
  <!-- Brief splash shown between `unlocked → locking → locked`. The
       backend's `vault-locked` event will resolve us to `locked` within
       milliseconds (lock just clears in-memory keys); this exists so
       the user sees a transient "Locking…" state rather than a flash
       of the Unlock screen with stale data still visible. -->
  <main class="locking-splash" aria-live="polite">
    <p class="locking-splash__label">Locking…</p>
  </main>
{:else}
  <Unlock />
{/if}

{#if $autoLockNotice}
  <!-- Spec §12 auto-lock notice surface. The AutoLockNotice union is
       narrow by construction (`manual` is filtered at the producer in
       `stores.ts::vaultLocked` — see the comment there for the
       altitude argument); every notice that lands in the store is
       intended to render. -->
  <Toast notice={$autoLockNotice} />
{/if}
