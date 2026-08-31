# YARA Rule Sets

Rules are organized by category, one directory per category. Each `.yar` file
should group related rules and use a `meta` block with at least `description`,
`severity`, and `author` fields so `modules/yara_engine.py` can map a rule
match to a `Finding` severity.

| Directory | Purpose |
|---|---|
| `network/` | Suspicious network-related strings (hardcoded IPs/URLs, raw sockets) |
| `execution/` | Shell access and command execution primitives |
| `crypto/` | Cryptographic routine detection (e.g. AES) |
| `anti_analysis/` | Debugger/emulator/sandbox detection techniques |
| `ics_malware/` | Known ICS/SCADA and power-sector malware indicators |
| `persistence/` | Boot/init persistence mechanisms |

See `docs/rule_writing.md` for a full guide on authoring new rules.
