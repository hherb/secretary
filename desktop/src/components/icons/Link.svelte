<script lang="ts">
  // Lucide "link" icon -- ISC/MIT, https://lucide.dev. Vendored (no runtime
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
  <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
  <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
</svg>
