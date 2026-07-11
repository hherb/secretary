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

  it('still scans a <script> block closed with a whitespace/attribute end tag', () => {
    // Regression for js/bad-tag-filter: the HTML tokenizer closes a script on any
    // `</script ...>` (trailing whitespace or ignored attributes). A tolerant end-tag
    // match must not drop the block — that would leave the ungated write below
    // UNSCANNED (a false negative). The attribute-bearing end tag locks the `[^>]*`
    // form: a bare `</script>` or whitespace-only `</script\s*>` regex fails here.
    const src = `
      <script lang="ts">
        async function onImport() {
          await importContact(path);
        }
      </script\n data-x>
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

  it('flags an ungated method-shorthand handler when a SIBLING method gates another write (#286)', () => {
    // The #280 sibling-gated bug class, but expressed as object method shorthand:
    // `good` gates shareBlock; `bad` must NOT inherit that gate for importContact.
    const src = `
      const handlers = {
        async good() {
          await authorizeWrite('Confirm sharing this block');
          await shareBlock(b, r);
        },
        async bad() {
          await importContact(path);
        },
      };`;
    const violations = scan(src);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ wrapper: 'importContact', functionName: 'bad' });
  });

  it('passes a gated method-shorthand handler (#286)', () => {
    const src = `
      const handlers = {
        async confirmSave() {
          await authorizeWrite('Confirm saving this entry');
          await saveRecord(uuid, rec);
        },
      };`;
    expect(scan(src)).toEqual([]);
  });

  it('detects get/set accessor method bodies (#286)', () => {
    const src = `
      const obj = {
        set value(v) {
          importContact(v);
        },
      };`;
    expect(scan(src).map((v) => v.functionName)).toEqual(['value']);
  });

  it('does NOT false-positive a write nested in an if-block under a gated handler (#286)', () => {
    // The control-flow exclusion: `if (...) {` must not be treated as a function body,
    // or the gate in the parent handler would not be seen as enclosing the nested write.
    const src = `
      async function confirmSave() {
        await authorizeWrite('Confirm saving this entry');
        if (dirty) {
          await saveRecord(uuid, rec);
        }
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('does NOT false-positive a write nested in a for/switch block under a gated handler (#286)', () => {
    const src = `
      async function bulkSave() {
        await authorizeWrite('Confirm saving these entries');
        for (const rec of recs) {
          switch (rec.kind) {
            case 'a':
              await saveRecord(rec.uuid, rec);
              break;
          }
        }
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('does NOT false-positive a write nested in a while/with block under a gated handler (#286)', () => {
    // Locks the rest of NON_METHOD_KEYWORDS that the if/for/switch/catch fixtures
    // above do not directly exercise — `while` and `with` must also be excluded as
    // bodies, or the parent gate would not be seen as enclosing the nested write.
    const src = `
      async function bulkSave() {
        await authorizeWrite('Confirm saving these entries');
        while (more) {
          await saveRecord(u, r);
        }
        with (ctx) {
          await saveRecord(u, r);
        }
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('recognizes a method-shorthand body carrying a TS return-type annotation (#286)', () => {
    // The `): Promise<void> {` form puts a `:` (not `=>`) after the param list, so the
    // arrow-exclusion must NOT fire and the annotated body must still be scanned.
    const src = `
      const handlers = {
        async save(rec: Rec): Promise<void> {
          await saveRecord(rec.uuid, rec);
        },
      };`;
    const violations = scan(src);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ wrapper: 'saveRecord', functionName: 'save' });
  });

  it('does NOT false-positive a write nested in a catch block under a gated handler (#286)', () => {
    const src = `
      async function confirmSave() {
        await authorizeWrite('Confirm saving this entry');
        try {
          await primarySave(rec);
        } catch (e) {
          await saveRecord(uuid, rec);
        }
      }`;
    expect(scan(src)).toEqual([]);
  });

  // #408: the call-site matcher was comment-naive — a wrapper name with call syntax
  // mentioned inside a comment was matched as a real ungated call. It must ignore
  // comments and string literals, while still catching genuine executable calls.
  it('does NOT flag a gated wrapper mentioned with call syntax inside a line comment (#408)', () => {
    const src = `
      async function onImport() {
        // calls importContact(path) after authorizeWrite — described, not invoked
        await authorizeWrite('Confirm importing this contact');
        await realImport(path);
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('does NOT flag a gated wrapper mentioned with call syntax inside a block comment (#408)', () => {
    const src = `
      /**
       * This handler eventually reaches saveRecord(uuid, rec) via the store.
       */
      async function describe2() {
        await readBlock(b);
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('still flags a genuine ungated call sitting next to a comment mention (#408)', () => {
    // A comment mentioning the wrapper must not mask a real ungated call in the same body.
    const src = `
      async function bad() {
        // saveRecord(uuid, rec) is what this does
        await saveRecord(uuid, rec);
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecord']);
  });

  it('does not mistake `//` inside a string literal for a comment start (#408)', () => {
    // If the masker treated `//` in "https://..." as a line comment, it would blank the
    // rest of the line and the genuinely ungated saveRecord() after it would go UNSCANNED
    // (a false NEGATIVE — the dangerous direction). The real call must still trip.
    const src = `
      async function bad() {
        const url = 'https://example.com/x'; await saveRecord(uuid, rec);
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecord']);
  });

  it('does NOT flag a gated wrapper name that only appears inside a string literal (#408)', () => {
    const src = `
      async function log() {
        console.log('about to call saveRecord(uuid, rec)');
      }`;
    expect(scan(src)).toEqual([]);
  });

  it('STILL flags a real ungated call inside a template-literal interpolation (#408)', () => {
    // Masking string bodies must NOT blank `${...}` interpolation code — a call there is
    // executable and must still be caught, else masking would WEAKEN the gate.
    const src = `
      async function bad() {
        const msg = \`result: \${await saveRecord(uuid, rec)}\`;
        return msg;
      }`;
    expect(scan(src).map((v) => v.wrapper)).toEqual(['saveRecord']);
  });
});
