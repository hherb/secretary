<script lang="ts">
  // Lucide "pencil" icon -- ISC/MIT, https://lucide.dev. Vendored to match
  // the existing dependency-free icon set.
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
  <path d="M21.2 8.4 8.4 21.2a2 2 0 0 1-1.4.6H3v-4a2 2 0 0 1 .6-1.4L16.4 3.6a2.1 2.1 0 0 1 3 0l1.8 1.8a2.1 2.1 0 0 1 0 3Z" />
  <path d="m14.5 5.5 4 4" />
</svg>
