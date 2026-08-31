# HexWarden

Firmware trojan/malware detection toolkit for embedded and power-sector devices, built for Smart India Hackathon 2026 (SIH1387).

## Requirements

- Python >= 3.9
- `pip install -r requirements.txt`
- binwalk >= 2.3 (`apt install binwalk`)

## Binwalk Backend

HexWarden uses Binwalk for firmware extraction and format identification.
Two backends are supported and selected automatically:

| Backend | How to activate | Status |
|---|---|---|
| Subprocess (default) | `apt install binwalk` | ✅ Active |
| Python API (faster) | `git clone https://github.com/ReFirmLabs/binwalk && cd binwalk && pip install .` | Activates automatically when installed |

> ⚠️ **Warning:** `pip install binwalk` from PyPI installs an outdated
> unmaintained version (2.x). Install from source for full format support.
> The subprocess backend (`apt install binwalk`) is recommended for most
> users and is what HexWarden defaults to.

To check which backend is active, run with `--verbose` and look for:
`INFO Binwalk backend: SUBPROCESS` or `INFO Binwalk backend: API`

## TODO

- [ ] Project description and motivation
- [ ] Architecture overview (see `docs/architecture.md`)
- [ ] Installation instructions
- [ ] Usage examples (see `docs/usage.md`)
- [ ] Supported firmware/architectures (ESP32, STM32, ARM, MIPS, ...)
- [ ] Module overview (entropy, strings, imports, YARA, crypto constants, filesystem, dynamic analysis)
- [ ] Rule writing guide (see `docs/rule_writing.md`)
- [ ] Contributing guidelines
- [ ] License
- [ ] Acknowledgements / SIH1387 context
