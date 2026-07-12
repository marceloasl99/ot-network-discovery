# Changelog

## 1.0.0 - 2026-07-12

### Added

- Correct CIDR network and broadcast calculation for arbitrary IPv4 prefixes
- Automatic or explicit interface selection
- Passive-only discovery mode
- Bounded parallel ICMP discovery
- Configurable timeout, throttle and host limit
- Multiple neighbor-state support
- Optional reverse-DNS resolution
- CSV, JSON, summary and structured log reports
- Large-subnet warnings and deterministic error handling
- GitHub documentation and security guidance

### Changed

- Replaced directed-broadcast ping dependency with bounded per-address discovery
- Replaced Reachable-only filtering with operationally useful neighbor states
- Added explicit UTF-8 report encoding and stable report fields
