<script lang="ts">
  type Props = {
    size?: number;
    class?: string;
  };

  let { size = 40, class: className = '' }: Props = $props();
</script>

<!-- A compact, single-colour companion to the detailed application artwork.
     It stays legible in the title bar and at small desktop icon sizes, where
     the full shaded illustration loses its keyhole and quill silhouette. -->
<svg
  class={`brand-mark ${className}`}
  width={size}
  height={size}
  viewBox="0 0 48 48"
  fill="none"
  xmlns="http://www.w3.org/2000/svg"
  aria-hidden="true"
>
  <path
    d="M12.5 11.5h20a4 4 0 0 1 4 4v22h-20a5 5 0 0 1-5-5v-16a5 5 0 0 1 5-5Z"
    stroke="currentColor"
    stroke-width="2.5"
    stroke-linejoin="round"
  />
  <path
    d="M16.5 37.5a5 5 0 0 1 0-10h20"
    stroke="currentColor"
    stroke-width="2.5"
    stroke-linecap="round"
  />
  <path
    d="M29.5 8.5c5.5-3 9.2-1.9 10.5-.7-.2 5.2-2.7 10.2-8.2 14.1l-6.3 4.5 2.8-7.4c-2.1.7-3.8 1.8-5.3 3.3 1-5.7 3.2-10 6.5-13.8Z"
    fill="currentColor"
    stroke="currentColor"
    stroke-width="1.25"
    stroke-linejoin="round"
  />
  <path
    d="m23 28 10.5-13.5"
    stroke="var(--brand-mark-ink, #17233f)"
    stroke-width="1.5"
    stroke-linecap="round"
  />
  <path
    d="M22.5 30.5a3 3 0 1 0-3.7 2.9v2.1h2.4v-2.1a3 3 0 0 0 1.3-2.9Z"
    fill="currentColor"
  />
</svg>
