# Technical Review of the Original Script

## Main findings

1. The subnet computation changed only the fourth octet, so prefixes other than `/24` could produce an invalid broadcast address.
2. Directed-broadcast ICMP is commonly blocked or ignored and is not a dependable discovery mechanism on Windows or OT assets.
3. Filtering only `Reachable` neighbors discarded useful `Stale`, `Delay`, `Probe` and `Permanent` entries.
4. The original pipeline formatting and escaped characters were fragile after being copied through rich text.
5. `Tee-Object` was used without `-Append` in one failure path, which could overwrite earlier log content.
6. CSV encoding and stable output fields were not explicitly controlled.
7. Multi-homed hosts could produce an array of configurations, breaking scalar assumptions.
8. There was no activity limit for large prefixes.
9. Errors, report metadata and passive-only operation were limited.

## Design choices in the revised version

- Correct 32-bit CIDR arithmetic
- Per-address bounded ICMP rather than broadcast ping
- Passive-first switch for sensitive environments
- Host-count ceiling
- Explicit interface selection
- Structured outputs and timestamps
- No port scanning, authentication or device modification
