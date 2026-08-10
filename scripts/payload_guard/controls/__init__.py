"""Self-test control corpora (#474, #480, #486): `core` holds rule E1's
POSITIVE_CONTROLS / NEGATIVE_CONTROLS, `bridge` holds rules E2-E4's
BRIDGE_POSITIVE_CONTROLS / BRIDGE_NEGATIVE_CONTROLS / SELF_TEST_DETAIL_SRC,
`wrapper` holds the WRAPPER_POSITIVE_CONTROLS / WRAPPER_NEGATIVE_CONTROLS
for the wrapper-root rule set — rules E2/E3 and E5. It was written for rule
E3's shape 5, which #497/#500 retired on every root; `WP7` now pins that
shape DENYING, and E5 is the acceptance the wrapper roots still have and the
bridge does not.
See the entry point's docstring for the full rule statement; see
`payload_guard.selftest` for the harness that runs these corpora.
"""
