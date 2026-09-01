"""§11 CRDT merge, implemented from the spec docs alone.

Required to agree bit-for-bit with `core/src/vault/conflict.rs` on every
committed KAT. If a change here needs a KAT to be regenerated, that is a
protocol change and the spec doc is the first thing to update.
"""
