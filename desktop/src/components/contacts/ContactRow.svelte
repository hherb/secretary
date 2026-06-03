<script lang="ts">
  // One imported contact: display name + how many of the owner's blocks it
  // receives, plus a Delete action. Mirrors TrashedBlockRow's callback-prop
  // shape. The parent owns the confirm dialog + delete call.
  import type { ContactSummaryDto } from '../../lib/ipc';

  type Props = {
    contact: ContactSummaryDto;
    onDelete: (c: ContactSummaryDto) => void;
  };
  let { contact, onDelete }: Props = $props();

  const blocksLabel = $derived(
    contact.sharedBlockCount === 1
      ? 'receives 1 block'
      : `receives ${contact.sharedBlockCount} blocks`
  );
</script>

<div class="contact-row">
  <span class="contact-row__name">{contact.displayName}</span>
  <span class="contact-row__count">{blocksLabel}</span>
  <button type="button" class="contact-row__delete" onclick={() => onDelete(contact)}>
    Delete
  </button>
</div>
