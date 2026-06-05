<script lang="ts">
  // Lucide "lock" icon -- ISC/MIT, https://lucide.dev. Vendored (no runtime
  // dep). Presentational: aria-hidden; colour via currentColor (inherits the
  // surrounding text token, so light/dark themes need no extra rules).
  type Props = { size?: number };
  let { size = 20 }: Props = $props();
</script>

<svg
  class="icon"
  xmlns="http://www.w3.org/2000/svg"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
</svg>
