# Final polishing TODOs

Non-blocking follow-ups carried over from the PR #9 review (vault: defensive
death-clock clamp + tag canonicalisation + Python unknown-merge KAT). None of
these are regressions or correctness issues; they are deferred polish items
to be picked up when adjacent code is next touched.

---

## 1. Lift the cross-language hex compare pattern into a helper if a second hex-bearing KAT field appears

**Where:** [core/tests/python/conformance.py:1914-1949](core/tests/python/conformance.py#L1914-L1949) (`py_merge_unknown_map`)

The case-insensitivity bug fixed in commit `2cb7202` (raw string compare on hex
disagreeing with Rust's `u8::from_str_radix` byte-level decoding) is currently
guarded by Section 5 for `unknown_hex` only. The pattern is:

* compare via `bytes.fromhex(...)` (case-insensitive, byte-exact)
* re-emit via `bytes.hex()` (lowercase canonical)

If a future KAT field carries hex blobs (e.g., a v2 key-bytes field, a
fingerprint comparison field), this same pattern needs to apply or the same
class of cross-language drift can re-appear. Lifting `hex_lex_compare(a, b) ->
int` and `hex_canonicalise(s) -> str` helpers into `conformance.py` (or a
small shared utilities module) would prevent the regression.

Out of scope for this PR — only one call site exists today.

---

## 2. Extract a `_record_pass_fail()` helper if Section 6 lands

**Where:** [core/tests/python/conformance.py:2381-2441](core/tests/python/conformance.py#L2381-L2441)
(Section 5 — `section5_unknown_map_case_insensitivity`)

Each Section 5 sub-test follows the same shape:

```python
got = py_merge_unknown_map(...)
if got["k"].lower() != expected:
    lines.append(f"FAIL  {description}: ...")
    all_ok = False
else:
    lines.append(f"PASS  {description}")
```

Three sub-tests is fine inline. If a Section 6 lands with five or more
sub-tests, extract a small `_record(condition: bool, description: str, lines:
list[str]) -> bool` helper to drop the boilerplate. Match Sections 1–4's
established style — don't introduce a real test framework just for this.

Defer until Section 6 is actually being written.

---

## How to close items

When picking one up, drop the section from this file in the same commit that
ships the change. If this file becomes empty, delete it — its job is done.
