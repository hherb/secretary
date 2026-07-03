import { describe, it, expect } from 'vitest';
import {
  COMMAND_CLASSIFICATION,
  classifiedCommandNames,
  gatedWrappers,
  exemptWritesMissingReason,
} from '../src/lib/writeCommands';

describe('writeCommands registry', () => {
  it('classifies exactly the 38 registered commands', () => {
    expect(classifiedCommandNames().size).toBe(38);
  });

  it('lists the gated write wrappers (14)', () => {
    const w = gatedWrappers();
    expect(w).toContain('saveRecord');
    expect(w).toContain('importContact');
    expect(w).not.toContain('createVault'); // exempt
    expect(w).not.toContain('listBlocks'); // read
    expect(w).toHaveLength(14);
  });

  it('requires every exempt write to record a reason', () => {
    expect(exemptWritesMissingReason()).toEqual([]);
  });

  it('marks every gated/exempt entry as kind write with a wrapper', () => {
    for (const [cmd, c] of Object.entries(COMMAND_CLASSIFICATION)) {
      if (c.gate) {
        expect(c.kind, cmd).toBe('write');
        expect(c.wrapper, cmd).toBeTruthy();
      }
    }
  });
});
