# HexWarden

**Firmware trojan / malware detection toolkit for embedded and power-sector devices.**
Built for Smart India Hackathon 2026 — problem statement **SIH1387: Detection of
Embedded Malware/Trojan in Hardware Devices (Power Sector)**.

Malware hidden in power-sector hardware firmware sits below the OS, invisible to
antivirus, and can trigger blackouts on command — Industroyer did exactly this to
Ukraine's power grid in 2016. HexWarden runs a firmware image through several
independent detection layers and combines their findings into one scored verdict.
No single signal issues a verdict on its own.

## Detection layers

| Layer | Module(s) | What it catches |
|---|---|---|
| Entropy analysis | `modules/entropy.py`, `modules/firmware_pipeline.py` | Encrypted / compressed injected payloads — via CFAR guard-band local contrast (a region that stands out from *its own neighborhood*, not a fixed global threshold) |
| Golden-image diff (Mode A) | `modules/golden_diff.py` | Exactly what changed between a known-clean reference and a suspect image — content-defined chunking, threshold-independent |
| YARA signatures | `modules/yara_engine.py` + `rules/` | Known ICS-malware / backdoor / packer signatures (Industroyer, Triton, BlackEnergy, HAVEX, …), with clean-baseline suppression |
| Filesystem forensics | `modules/filesystem.py` | Backdoor UID-0 accounts, suspicious cron/init persistence, pre-installed SSH keys, executables in runtime-only dirs, world-writable system files |
| String analysis | `modules/strings.py` + `config/string_patterns.json` | Hardcoded C2 IPs, shell commands, credential patterns, base64 blobs (decoded + re-scanned), C2 ports |
| Network monitor | `modules/dynamic/network_monitor.py` | C2 beacon timing, DNS tunneling, suspicious outbound connections, plaintext-on-443 evasion — from a `.pcap` capture |
| Scoring engine | `core/scoring.py` | Combines all layers into one 0–100 score + LOW / MEDIUM / HIGH / CRITICAL verdict, with a cross-module corroboration bonus |

Scaffolded but not yet implemented: `modules/crypto_constants.py`, `modules/imports.py`,
`modules/dynamic/syscall_tracer.py`, `core/pipeline.py`.

## Requirements

- Python >= 3.9
- `pip install -r requirements.txt` (numpy, matplotlib, yara-python, scapy, pyelftools, flask, flask-cors, pytest)
- binwalk >= 2.3 (`apt install binwalk`) — see [Binwalk Backend](#binwalk-backend)

## Web Dashboard

The dashboard is the primary way to run a **scored** analysis. The CLI (below) runs
the modules and lists findings; only the dashboard runs `core/scoring.py` to produce
the combined verdict, entropy plot, and side-by-side comparison.

```bash
python3 web/run.py          # or:  python3 -m web.run
```

Then open **http://localhost:5000**.

- **Landing** (`/`) — project overview.
- **Dashboard** (`/dashboard`) — drag-and-drop a firmware image (required), plus
  optionally a **golden reference firmware** (enables golden-image diff) and/or a
  **`.pcap` capture** (enables the network monitor). Progress streams live over
  Server-Sent Events while the pipeline runs.
- **Report** (`/scan/<id>`) — verdict badge + score, per-module breakdown, embedded
  entropy plot, sortable/filterable/paginated findings table, corroborated-findings
  section, "Download JSON Report".
- **About** (`/about`) — the problem, the modules, the team.
- **Compare** (`/compare?a=<id>&b=<id>`) — two scans side by side (clean vs trojaned
  score). Tick two rows in the scan history, then hit "Compare Selected".
- Scan-history rows can be deleted (trash icon → confirm).

Uploaded files live under `web/uploads/<scan_id>/` and are deleted once the scan
finishes (only the entropy plot in `output/` is kept). Scan records live in
`web/hexwarden.db` (SQLite). Both are gitignored.

> **Note:** dashboard scans currently run the raw-binary YARA and string passes
> twice — once inside `firmware_pipeline.run_pipeline()` (findings tagged `*_raw`)
> and once directly from the web layer (tagged without `_raw`). The duplicate
> findings show up in the report but don't move the verdict band. Cleanup pending.

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

## Running HexWarden (CLI)

`main.py` runs the selected modules and prints a findings summary (severity counts
plus the highest-scoring findings). It does **not** compute the aggregate scored
verdict — use the [web dashboard](#web-dashboard) for that.

`--modules` accepts `entropy`, `filesystem`, `golden_diff`, `pipeline` (default).
`pipeline` runs Binwalk extraction, raw-binary entropy, an **unconditional
raw-binary YARA pass** (`module_name="yara_engine_raw"`) and **raw-binary string
pass** (`strings_raw`) — these run even when Binwalk extracts nothing (ESP32 /
bare-metal firmware) — then filesystem checks, then the extracted-file entropy
walk, then cleanup (the extraction directory is always removed; only findings and
the report/plot in `output/` survive).

### Core Commands

All commands run from the repository root.

**1. Full pipeline on a single firmware**

```bash
python3 main.py --firmware <path> --verbose
```

**2. Golden-image diff (Mode A)** — compares a suspect firmware against a
known-clean reference using content-defined chunking. The most reliable mode when
you have a clean reference: it compares actual bytes rather than relying on entropy
thresholds (see [Known Limitations](#known-limitations--entropy-detection)).

```bash
python3 -m modules.golden_diff --golden <clean-firmware> --suspect <suspect-firmware> -v
```

**3. Filesystem checks standalone** — backdoor accounts, cron persistence,
SSH `authorized_keys`, suspicious-executable-location, world-writable-file checks
against an already-extracted firmware filesystem. Takes a directory, not a firmware
file — use command 7 (manual extraction) first if you don't already have one.

```bash
python3 -m modules.filesystem <extracted-directory> -v
```

**4. Entropy analysis standalone** — Shannon entropy + local-contrast detection on
a single file, outside the full pipeline (no Binwalk cross-referencing, no
filesystem checks).

```bash
python3 -m modules.entropy <firmware-path> -v
```

**5. YARA scan standalone** — runs the rule set in `rules/` against a firmware file
or an extracted-firmware directory.

```bash
python3 -m modules.yara_engine <firmware-path> -v
```

Also accepts `-r/--rules <dir>` (default `rules/`), `-g/--golden <path>` to suppress
matches also present in a clean baseline, `--raw-image <path>` to also scan a raw
image alongside a directory target, `--show-suppressed` to include baseline-matched
hits, and `-o/--output <file>` to write JSON.

**6. String analysis standalone** — pure-Python ASCII (min 4 chars) + UTF-16LE
string extraction, scanned against the pattern library in
`config/string_patterns.json`. Detects hardcoded IPs, suspicious domains, shell
commands, credential patterns, base64 blobs (decoded and re-scanned one level
deep), and C2 ports. Writes `output/report_strings_*.json`.

```bash
python3 -m modules.strings <firmware-path> -v
```

**7. Network monitor standalone** — analyzes a `.pcap` / `.pcapng` capture for
suspicious C2 communication: suspicious destinations, malicious payload content
(TLS-aware, with SNI extraction), DNS-tunneling indicators, and regular beacon
timing. Works against real hardware captures or synthetic pcaps. Writes
`output/report_network_monitor_*.json`.

```bash
python3 -m modules.dynamic.network_monitor <capture.pcap> -v
```

**8. Manual firmware extraction** — use this when you need an extracted directory
for standalone `filesystem.py` testing (command 3), or to inspect Binwalk's output
by hand:

```python
from pathlib import Path
from modules import binwalk_wrapper

result = binwalk_wrapper.extract('<firmware-path>', Path('<output-dir>'))
print('Extracted to:', result.extracted_dir)
```

> **Note:** the `output_dir` argument is accepted for interface compatibility but
> the subprocess backend ignores it — Binwalk always extracts to its own fixed
> `_<firmware_filename>.extracted` directory (next to the firmware file, or in the
> current working directory if the firmware lies outside it). Always use
> `result.extracted_dir` for the real location. This command does **not**
> auto-cleanup — delete the extracted directory yourself when you're done.

**9. Run the automated test suite** — run this after any code change.

```bash
python3 -m pytest tests/ -v      # 44 tests
```

**10. Check latest outputs**

```bash
ls -lt output/ | head -5
```

### How scoring works — `core/scoring.py`

`score(findings, modules_run=...)` returns a `ScanScore`:

- **Per-module, per-severity weights** (`MODULE_WEIGHTS`) — a CRITICAL from
  `golden_diff` (byte-diff against a clean reference) is worth more than a CRITICAL
  from `strings` (heuristic pattern match).
- **Corroboration bonus** — when 2+ *different* modules flag the same byte region
  (within `CORROBORATION_WINDOW_BYTES` = 4 KB), each of those findings gets +20%.
  This is the strongest signal the engine produces. Findings with no byte offset
  (e.g. filesystem checks) can't corroborate.
- **Normalization** — raw weighted sum → `min(100, raw / config.SCORING_EXPECTED_MAX * 100)`
  (`SCORING_EXPECTED_MAX = 500`, tuned so a clean DD-WRT run lands in 0–25).
- **Verdict bands** — 0–25 LOW (green) · 26–50 MEDIUM (yellow) · 51–75 HIGH (orange) · 76+ CRITICAL (red).
- **Confidence** — fraction of the module registry that actually *ran* this scan.
  A module that ran and found nothing is a passed check, not missing evidence — it
  does not lower confidence.

### Standard Testing Workflow — Comparing Clean vs Trojaned Firmware

A repeatable recipe for validating detection against a clean/trojaned firmware pair:

```bash
# 1. Confirm the two files are actually different (sanity check before testing)
stat -c '%s %n' <clean-firmware> <trojaned-firmware>

# 2. Golden-diff — the most reliable test when a clean reference exists
python3 -m modules.golden_diff --golden <clean-firmware> --suspect <trojaned-firmware> -v

# 3. Full pipeline on the clean firmware (establishes the baseline)
python3 main.py --firmware <clean-firmware> --verbose

# 4. Full pipeline on the trojaned firmware (compare its summary against step 3)
python3 main.py --firmware <trojaned-firmware> --verbose
```

Compare the summary lines from steps 3 and 4 side by side. A healthy result shows
the trojaned firmware's finding count and severity breakdown close to the clean
baseline, with a small number of additional findings tracing to the actual injected
content. A large, unexplained discrepancy — especially the clean firmware showing
*more* findings than the trojaned one — indicates a bug, not a detection success.
This exact pattern (97 HIGH findings on clean vs. 5 on trojaned, from the same
underlying regions) caught a real false-positive/non-determinism bug during
development; see commit `31272fa` ("Fix entropy false-positive/non-determinism").

For a **scored** side-by-side, upload both images to the [web dashboard](#web-dashboard)
and use **Compare Selected** on the two history rows.

### Known Limitations — Entropy Detection

Shannon entropy on small windows (256 bytes) has statistical bias: true random data
(`os.urandom()`) averages **~7.17 bits/byte** in a 256-byte window, not 8.0, due to
small-sample variance (256 draws over 256 possible byte values collide often enough
to pull the estimate well below the theoretical maximum). This means a well-padded
or statistically-tuned malicious payload can produce entropy similar to the
firmware's own legitimate compressed regions (which often sit in the 7.0–7.5 range
for the same reason), potentially evading pure entropy-based detection — most
pronounced on firmware that is *already* densely compressed (squashfs/LZMA/XZ) end
to end, where there's no low-entropy neighborhood left for an injected payload to
contrast against either.

This is why HexWarden treats entropy as one signal among several — not the sole
detector — and why golden-image diffing (Mode A) exists as an independent detection
layer: diff-based detection compares actual bytes against a known-clean reference
and does not depend on entropy thresholds at all. **When a clean reference is
available, prefer golden-image diff** (command 2 above).

### Known Limitations — CLI Does Not Score

`main.py` lists findings and severity counts but does **not** run `core/scoring.py`
— there is no verdict line in CLI output. Run the [web dashboard](#web-dashboard)
for the aggregate LOW / MEDIUM / HIGH / CRITICAL verdict.

### Known Limitations — Bare-Metal / ESP32 Firmware

Binwalk cannot carve a filesystem out of a raw ESP32 application image, so the
filesystem-forensics and extracted-file-entropy layers contribute nothing there —
detection falls back to the raw-binary YARA + string passes (`yara_engine_raw`,
`strings_raw`). A trojan that only embeds a **bare C2 IP** (no `IP:PORT`, no nearby
`connect`/`socket` string) currently registers as a single isolated LOW string
finding, which can tie a clean image's score. Tightening the
`FW_Hardcoded_C2_Endpoint` YARA rule to also match a bare IP, or raising the
isolated-`hardcoded_ip` severity in `modules/strings.py`, would close this.

### Test Firmware Generation

To build a synthetic trojaned firmware for testing, append a payload combining:

1. A high-entropy blob for entropy/golden-diff testing — note that `os.urandom()`
   may not read as high-entropy at small window sizes (see
   [Known Limitations](#known-limitations--entropy-detection) above); prefer a
   byte-permutation-based blob (e.g. `bytes(range(256)) * N`, which gives every
   256-byte window exactly one of each byte value, a deterministic peak entropy of
   8.0) for reliable entropy-detection testing.
2. Suspicious ASCII strings (fake C2 IPs, shell commands, credentials) for
   YARA/string-matching testing — cluster several *different* categories within
   512 bytes to exercise the string-analysis co-occurrence escalation.
3. Known cryptographic constants (e.g. AES S-box bytes) for crypto-signature testing.

See `tests/test_firmware_pipeline.py`'s `_MAX_ENTROPY_BLOB` for the exact
byte-permutation-blob pattern used by the automated test suite, which correctly
avoids the `os.urandom()` small-window bias described above.

## Project Layout

```
main.py                        CLI entry point (runs modules, prints findings)
config.py                      all tunable thresholds / weights
config/string_patterns.json    editable string-pattern library
core/
  scoring.py                   weighted verdict aggregation (used by the dashboard)
modules/
  entropy.py                   Shannon entropy + local contrast
  firmware_pipeline.py         Binwalk extract + raw/extracted entropy + raw YARA/strings + filesystem
  binwalk_wrapper.py           Binwalk backend abstraction (subprocess / Python API)
  golden_diff.py               content-defined-chunking diff (Mode A)
  yara_engine.py               YARA wrapper + clean-baseline suppression
  filesystem.py                extracted-filesystem forensics
  strings.py                   string extraction + pattern matching
  dynamic/network_monitor.py   pcap C2 / beacon / DNS-tunnel analysis
rules/                         YARA rule sets (ICS protocols, backdoors, packers, crypto, persistence, …)
web/                           Flask dashboard — app.py, database.py, run.py, templates/, static/
tests/                         pytest suite (44 tests)
docs/                          architecture.md, usage.md, rule_writing.md
```

## Team

**HexWarden** — Thapar Institute of Engineering & Technology
SIH1387 · Theme: Blockchain & Cybersecurity · Category: Hardware
<https://github.com/varun935/HexWarden>

| Member | Role |
|---|---|
| Varun Chaitenya Sharma | Team Lead, Core Architecture, Reverse Engineering |
| Tejas Wasan | YARA Engine, String Analysis |
| Dhairya Mittal | Hardware, Side-Channel Analysis |
| Dakshit Chopra | Hardware, Firmware Extraction |
| Viresh Arora | Report Generation, Testing |
| Jayana Sapra | Documentation, Scoring Engine |
