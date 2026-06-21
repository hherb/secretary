import { describe, it, expect } from 'vitest';
import { findUngatedWrites } from '../src/lib/writeGateScanner';

const GATED = ['saveRecord', 'saveRecordEdit', 'shareBlock', 'importContact', 'tombstoneRecord'];
const scan = (src: string, svelte = false) => findUngatedWrites(src, svelte, GATED);

describe('findUngatedWrites', () => {
  it('passes a gated wrapper preceded by authorizeWrite in the same function', () => {
    const src = `
      async function confirmSave() {
        await authorizeWrite('Confirm saving this entry');
        await saveRecord(uuid, rec);
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('flags an ungated handler even when a SIBLING handler gates another write (importContact class)', () => {
    const src = `
      async function confirmShare() {
        await authorizeWrite('Confirm sharing this block');
        await shareBlock(b, r);
      }
      async function onImport() {
        await importContact(path);
      }`;
    const violations = scan(src);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ wrapper: 'importContact', functionName: 'onImport' });
  });

  it('flags a write when the gate appears AFTER it in the same function', () => {
    const src = `
      async function bad() {
        await saveRecord(uuid, rec);
        await authorizeWrite('too late');
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecord']);
  });

  it('detects named arrow-function handlers', () => {
    const src = `const onDelete = async () => { await tombstoneRecord(b, r); };`;
    expect(scan(src).map((v) => v.functionName)).toEqual(['onDelete']);
  });

  it('discriminates saveRecord from saveRecordEdit (word boundary)', () => {
    // gate names saveRecord; saveRecordEdit is a DIFFERENT gated wrapper with no gate here
    const src = `
      async function edit() {
        await saveRecordEdit(b, r, rec);
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecordEdit']);
  });

  it('ignores read-only wrapper calls in an ungated function', () => {
    const src = `async function load() { const x = await listBlocks(); await readBlock(b); }`;
    expect(scan(src)).toEqual([]);
  });

  it('flags a gated write called at module top level (no enclosing function)', () => {
    const src = `const x = 1;\nsaveRecord(uuid, rec);`;
    const violations = scan(src);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ wrapper: 'saveRecord', functionName: '<top-level>' });
  });

  it('extracts the <script> block from a .svelte file', () => {
    const src = `
      <script lang="ts">
        async function confirmSave() {
          await authorizeWrite('ok');
          await saveRecord(b, r);
        }
      </script>
      <div>markup with the word saveRecord( in text should be ignored</div>`;
    expect(findUngatedWrites(src, true, GATED)).toEqual([]);
  });

  it('still scans a <script> block closed with a whitespace end tag (</script >)', () => {
    // Regression for js/bad-tag-filter: a tolerant end-tag match must not drop the
    // block (which would leave the ungated write below UNSCANNED — a false negative).
    const src = `
      <script lang="ts">
        async function onImport() {
          await importContact(path);
        }
      </script >
      <div/>`;
    const violations = findUngatedWrites(src, true, GATED);
    expect(violations.map((v) => v.wrapper)).toEqual(['importContact']);
  });

  it('does not treat braces inside template-literal strings as block boundaries', () => {
    const src = `
      async function confirmSave() {
        const msg = \`hello \${name} { not a block }\`;
        await authorizeWrite('ok');
        await saveRecord(b, r);
      }`;
    expect(scan(src)).toEqual([]);
  });
});
