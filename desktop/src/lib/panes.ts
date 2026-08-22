// #526 — the three-pane projection.
//
// The nine-arm `browseNav` union is unchanged; this maps each arm onto four
// slots. Keeping it a pure projection rather than new store state means every
// existing guard (shouldPopOnEscape, resetBrowse, the trash and rename flows)
// keeps its current tests and needs no re-audit — the panes are a VIEW of
// state that is already proven, and this file's own test is the design's
// projection table made executable.

import type { BrowseNav } from './browse';
import type { BlockSummaryDto, RecordDto } from './ipc';

export const SELECT_BLOCK_PROMPT = 'Select a block';
export const SELECT_RECORD_PROMPT = 'Select a record';

export type SidebarSelection =
  | { kind: 'none' }
  | { kind: 'block'; blockUuidHex: string }
  | { kind: 'trash' }
  | { kind: 'contacts' };

export type ListPane =
  | { kind: 'prompt'; message: string }
  | {
      kind: 'records';
      block: BlockSummaryDto;
      selectedRecordUuidHex: string | null;
      /** Set while an editor occupies the detail pane. This frontend has NO
          dirty-tracking, so any navigation away from an open editor discards
          the draft silently — freezing is what stops a stray click doing that.
          It is the single source of truth for THREE consumers, not just this
          pane: RecordList's rows and its "+ Add record" button, and — via
          Vault.svelte — the entire left sidebar (every BlockCard, Trash,
          Contacts, "+ New block"). Widen all three together, and keep the
          `detail.kind === 'editor'` ⇒ `frozen` invariant that
          panes.test.ts asserts over every arm. */
      frozen: boolean;
    }
  | { kind: 'trash' }
  | { kind: 'contacts' };

export type DetailPane =
  | { kind: 'empty' }
  | { kind: 'prompt'; message: string }
  | { kind: 'viewer'; block: BlockSummaryDto; record: RecordDto }
  | { kind: 'editor'; block: BlockSummaryDto; record: RecordDto | null }
  /** The list pane occupies both right-hand columns; nothing renders here. */
  | { kind: 'spanned' };

export type ModalPane =
  | { kind: 'none' }
  | {
      kind: 'blockName';
      mode: { kind: 'create' } | { kind: 'rename'; block: BlockSummaryDto };
    };

export interface PaneLayout {
  sidebar: SidebarSelection;
  list: ListPane;
  detail: DetailPane;
  modal: ModalPane;
}

function blockSelected(block: BlockSummaryDto): SidebarSelection {
  return { kind: 'block', blockUuidHex: block.blockUuidHex };
}

function recordsIn(
  block: BlockSummaryDto,
  selectedRecordUuidHex: string | null,
  frozen: boolean
): ListPane {
  return { kind: 'records', block, selectedRecordUuidHex, frozen };
}

const NO_MODAL: ModalPane = { kind: 'none' };
const BLOCK_PROMPT: ListPane = { kind: 'prompt', message: SELECT_BLOCK_PROMPT };

export function panesFor(nav: BrowseNav): PaneLayout {
  switch (nav.level) {
    case 'blocks':
      return {
        sidebar: { kind: 'none' },
        list: BLOCK_PROMPT,
        detail: { kind: 'empty' },
        modal: NO_MODAL
      };
    case 'newBlock':
      return {
        sidebar: { kind: 'none' },
        list: BLOCK_PROMPT,
        detail: { kind: 'empty' },
        modal: { kind: 'blockName', mode: { kind: 'create' } }
      };
    case 'records':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, false),
        detail: { kind: 'prompt', message: SELECT_RECORD_PROMPT },
        modal: NO_MODAL
      };
    case 'renameBlock':
      // The block stays selected behind the dialog. That is only HALF of
      // "cancelling lands the user where they were": this projection decides
      // what renders behind the dialog, and `back()` decides where Cancel and
      // a completed rename actually go. Both must agree — browse.ts's
      // renameBlock arm pops to `records` for this block, pinned by
      // browse.test.ts, because this file cannot observe it (#526 review).
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, false),
        detail: { kind: 'empty' },
        modal: { kind: 'blockName', mode: { kind: 'rename', block: nav.block } }
      };
    case 'fields':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, nav.record.recordUuidHex, false),
        detail: { kind: 'viewer', block: nav.block, record: nav.record },
        modal: NO_MODAL
      };
    case 'editRecord':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, nav.record.recordUuidHex, true),
        detail: { kind: 'editor', block: nav.block, record: nav.record },
        modal: NO_MODAL
      };
    case 'newRecord':
      return {
        sidebar: blockSelected(nav.block),
        list: recordsIn(nav.block, null, true),
        detail: { kind: 'editor', block: nav.block, record: null },
        modal: NO_MODAL
      };
    case 'trash':
      return {
        sidebar: { kind: 'trash' },
        list: { kind: 'trash' },
        detail: { kind: 'spanned' },
        modal: NO_MODAL
      };
    case 'contacts':
      return {
        sidebar: { kind: 'contacts' },
        list: { kind: 'contacts' },
        detail: { kind: 'spanned' },
        modal: NO_MODAL
      };
  }
}
