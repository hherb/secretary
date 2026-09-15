//! A byte-level walk over the first CBOR item: well-formedness first, then
//! crypto-design §6.2 rule 4 (#641).
//!
//! **Why it exists.** ciborium's `Value` reader is laxer than RFC 8949 and than
//! `docs/vault-format.md` §4.2's well-formedness list in three ways, measured
//! over the fuzz corpus: it reads `undefined` (`0xf7`) as `null`, it turns
//! bignum tags 2 and 3 into integers so a later parsed-tree rule-4 walk never
//! sees the tag, and it accepts nested indefinite-length string chunks. None of
//! those changes whether a record is accepted — none of the forms is canonical,
//! so the re-encode comparison rejects them all — but each changes WHICH error
//! is reported, and `core/tests/differential_replay.rs` compares that against
//! `conformance.py`. Walking the bytes before ciborium reports what the bytes
//! actually are.
//!
//! **What it checks.** RFC 8949 well-formedness plus §4.2's precondition list:
//! a truncated head, argument or payload; reserved additional-info 28-30; the
//! indefinite form on majors 0, 1 and 6; a break outside an indefinite
//! container; an indefinite-string chunk that is not a definite string of the
//! same major (§3.2.3); text that is not valid UTF-8, per string and per chunk;
//! a major-7 simple value other than false/true/null. Then rule 4: any tag
//! (bignum tags included) and any float.
//!
//! **Precedence.** A well-formedness fault anywhere in the item outranks a
//! rule-4 fault anywhere: the first tag or float is remembered and reported only
//! once the whole item has proven well-formed.
//!
//! **Iterative.** An explicit stack, no recursion and no depth cap of its own.
//! ciborium's recursion limit still applies to the parse that follows; that
//! residual is tracked by #667, not fixed here.
//!
//! **Pure.** It reads a byte slice and allocates only its container stack;
//! nothing it holds is a copy of a payload.
//!
//! Python's twin is `conformance_lib/codec/well_formed.py`'s `walk_body`.

use crate::cbor::{CborErrorKind, CborFault};

/// Why [`walk_first_item`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkFault {
    /// Not well-formed CBOR. The kind is `Io` when the input ended first,
    /// `Syntax` otherwise; the offset is that of the offending head.
    Malformed(CborFault),
    /// §6.2 rule 4: a tag, at `offset`.
    Tag { offset: usize },
    /// §6.2 rule 4: a float, at `offset`.
    Float { offset: usize },
}

const MAJOR_SHIFT: u8 = 5;
const AI_MASK: u8 = 0x1f;
const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
/// The largest additional-info value that is itself the argument.
const AI_DIRECT_MAX: u8 = 23;
const AI_ONE_BYTE: u8 = 24;
const AI_TWO_BYTES: u8 = 25;
const AI_FOUR_BYTES: u8 = 26;
const AI_EIGHT_BYTES: u8 = 27;
const AI_INDEFINITE: u8 = 31;
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
/// For major 7, additional-info 25/26/27 is a half/single/double float.
const AI_FLOAT16: u8 = AI_TWO_BYTES;
const AI_FLOAT32: u8 = AI_FOUR_BYTES;
const AI_FLOAT64: u8 = AI_EIGHT_BYTES;
const BREAK: u8 = 0xff;
const BITS_PER_BYTE: u32 = 8;
/// A map's items are keys and values.
const ITEMS_PER_MAP_ENTRY: u64 = 2;

struct Head {
    major: u8,
    ai: u8,
    /// `None` for the indefinite form.
    arg: Option<u64>,
    len: usize,
}

/// An open container.
enum Frame {
    /// A definite array or map, or a tag's single content item, with `left`
    /// items still to read (a map counts keys and values).
    Definite {
        left: u64,
    },
    IndefiniteArray,
    /// `mid_entry` is true after a key and before its value.
    IndefiniteMap {
        mid_entry: bool,
    },
}

fn end_of_input(offset: usize) -> CborFault {
    CborFault {
        kind: CborErrorKind::Io,
        offset: Some(offset),
    }
}

fn syntax(offset: usize) -> CborFault {
    CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(offset),
    }
}

fn read_head(bytes: &[u8], at: usize) -> Result<Head, CborFault> {
    let Some(&initial) = bytes.get(at) else {
        return Err(end_of_input(at));
    };
    let major = initial >> MAJOR_SHIFT;
    let ai = initial & AI_MASK;
    let arg_len = match ai {
        0..=AI_DIRECT_MAX => {
            return Ok(Head {
                major,
                ai,
                arg: Some(u64::from(ai)),
                len: 1,
            })
        }
        AI_ONE_BYTE => 1,
        AI_TWO_BYTES => 2,
        AI_FOUR_BYTES => 4,
        AI_EIGHT_BYTES => 8,
        AI_INDEFINITE => {
            // RFC 8949 §3.2: valid for strings, arrays and maps, and for
            // major 7 it is the break code. Never for integers or tags.
            return if matches!(major, MAJOR_UINT | MAJOR_NINT | MAJOR_TAG) {
                Err(syntax(at))
            } else {
                Ok(Head {
                    major,
                    ai,
                    arg: None,
                    len: 1,
                })
            };
        }
        _ => return Err(syntax(at)),
    };
    let Some(arg_bytes) = bytes.get(at + 1..at + 1 + arg_len) else {
        return Err(end_of_input(at));
    };
    let arg = arg_bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << BITS_PER_BYTE) | u64::from(*byte));
    Ok(Head {
        major,
        ai,
        arg: Some(arg),
        len: 1 + arg_len,
    })
}

/// The offset one past a string payload of `len` bytes starting at `start`,
/// checking UTF-8 for text. Faults are reported at the string's head.
fn payload_end(
    bytes: &[u8],
    head_at: usize,
    start: usize,
    len: u64,
    text: bool,
) -> Result<usize, CborFault> {
    let end = usize::try_from(len)
        .ok()
        .and_then(|len| start.checked_add(len));
    let Some(content) = end.and_then(|end| bytes.get(start..end)) else {
        return Err(end_of_input(head_at));
    };
    if text && std::str::from_utf8(content).is_err() {
        return Err(syntax(head_at));
    }
    Ok(start + content.len())
}

/// The offset one past the string whose head is at `head_at`.
fn string_end(bytes: &[u8], head_at: usize, head: &Head) -> Result<usize, CborFault> {
    let text = head.major == MAJOR_TEXT;
    let start = head_at + head.len;
    let Some(len) = head.arg else {
        return chunks_end(bytes, start, head.major, text);
    };
    payload_end(bytes, head_at, start, len, text)
}

/// The offset one past the break that ends an indefinite string's chunks.
fn chunks_end(bytes: &[u8], mut at: usize, major: u8, text: bool) -> Result<usize, CborFault> {
    loop {
        match bytes.get(at) {
            None => return Err(end_of_input(at)),
            Some(&BREAK) => return Ok(at + 1),
            Some(_) => {
                let chunk = read_head(bytes, at)?;
                // §3.2.3: every chunk is a DEFINITE string of the same major.
                // Its payload is read directly rather than through
                // `string_end`, so a chunk can never re-enter this loop.
                let Some(len) = chunk.arg.filter(|_| chunk.major == major) else {
                    return Err(syntax(at));
                };
                at = payload_end(bytes, at, at + chunk.len, len, text)?;
            }
        }
    }
}

/// Close every container whose items are complete, or whose break is next.
fn close_finished_containers(
    bytes: &[u8],
    pos: &mut usize,
    stack: &mut Vec<Frame>,
) -> Result<(), CborFault> {
    loop {
        let at_break = bytes.get(*pos) == Some(&BREAK);
        match stack.last() {
            Some(Frame::Definite { left: 0 }) => {
                stack.pop();
            }
            Some(Frame::IndefiniteArray) if at_break => {
                stack.pop();
                *pos += 1;
            }
            Some(Frame::IndefiniteMap { mid_entry }) if at_break => {
                if *mid_entry {
                    return Err(syntax(*pos));
                }
                stack.pop();
                *pos += 1;
            }
            _ => return Ok(()),
        }
    }
}

/// Account for one item about to be read inside `parent`.
fn count_one_item(parent: Option<&mut Frame>) {
    match parent {
        Some(Frame::Definite { left }) => *left -= 1,
        Some(Frame::IndefiniteMap { mid_entry }) => *mid_entry = !*mid_entry,
        Some(Frame::IndefiniteArray) | None => {}
    }
}

fn open_container(head: &Head) -> Frame {
    match (head.major, head.arg) {
        (MAJOR_ARRAY, Some(count)) => Frame::Definite { left: count },
        (_, Some(count)) => Frame::Definite {
            left: count.saturating_mul(ITEMS_PER_MAP_ENTRY),
        },
        (MAJOR_ARRAY, None) => Frame::IndefiniteArray,
        (_, None) => Frame::IndefiniteMap { mid_entry: false },
    }
}

/// Walk the first CBOR item in `bytes`; return the offset one past it.
///
/// See the module doc for what is checked and in what precedence.
pub(crate) fn walk_first_item(bytes: &[u8]) -> Result<usize, WalkFault> {
    let mut pos = 0usize;
    let mut stack: Vec<Frame> = Vec::new();
    let mut first_rule4: Option<WalkFault> = None;
    let mut started = false;
    loop {
        close_finished_containers(bytes, &mut pos, &mut stack).map_err(WalkFault::Malformed)?;
        if started && stack.is_empty() {
            return match first_rule4 {
                Some(fault) => Err(fault),
                None => Ok(pos),
            };
        }
        started = true;
        count_one_item(stack.last_mut());
        let head = read_head(bytes, pos).map_err(WalkFault::Malformed)?;
        match head.major {
            MAJOR_UINT | MAJOR_NINT => pos += head.len,
            MAJOR_BYTES | MAJOR_TEXT => {
                pos = string_end(bytes, pos, &head).map_err(WalkFault::Malformed)?;
            }
            MAJOR_ARRAY | MAJOR_MAP => {
                pos += head.len;
                stack.push(open_container(&head));
            }
            MAJOR_TAG => {
                first_rule4.get_or_insert(WalkFault::Tag { offset: pos });
                pos += head.len;
                stack.push(Frame::Definite { left: 1 });
            }
            _ => {
                match head.ai {
                    SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL => {}
                    AI_FLOAT16 | AI_FLOAT32 | AI_FLOAT64 => {
                        first_rule4.get_or_insert(WalkFault::Float { offset: pos });
                    }
                    // `undefined`, every unassigned simple value, the one-byte
                    // simple form, and a break outside an indefinite container.
                    _ => return Err(WalkFault::Malformed(syntax(pos))),
                }
                pos += head.len;
            }
        }
    }
}

#[cfg(test)]
mod tests;
