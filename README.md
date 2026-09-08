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

## Running HexWarden

A single reference for every way to invoke HexWarden — the full pipeline, each
module standalone, and the manual steps in between. All commands below are
run from the repository root.

### Core Commands

**1. Full pipeline on a single firmware** — the primary way to analyze one
firmware image end to end. Runs Binwalk extraction, raw-binary entropy
analysis, filesystem checks, extracted-file entropy analysis, then cleanup
(the extraction directory is always removed afterward — only findings and
the report/plot in `output/` survive).

```bash
python3 main.py --firmware <path> --verbose
```

**2. Golden-image diff (Mode A)** — compares a suspect firmware against a
known-clean reference using content-defined chunking. Use this whenever you
have a clean reference image: it's the most reliable detection mode, since it
compares actual bytes rather than relying on entropy thresholds (see
[Known Limitations](#known-limitations--entropy-detection) below).

```bash
python3 -m modules.golden_diff --golden <clean-firmware> --suspect <suspect-firmware> -v
```

**3. Filesystem checks standalone** — runs the backdoor-account,
cron-persistence, SSH-authorized-keys, suspicious-executable-location, and
world-writable-file checks against an already-extracted firmware filesystem.
Takes a directory, not a firmware file — use command 6 (manual extraction)
first if you don't already have one.

```bash
python3 -m modules.filesystem <extracted-directory> -v
```

**4. Entropy analysis standalone** — runs Shannon entropy + local-contrast
detection on a single file, outside the full pipeline (no Binwalk
cross-referencing, no filesystem checks, no cleanup step since nothing is
extracted).

```bash
python3 -m modules.entropy <firmware-path> -v
```

**5. YARA scan standalone** — runs the rule set in `rules/` against a
firmware file or an extracted-firmware directory directly.

```bash
python3 -m modules.yara_engine <firmware-path> -v
```

Also accepts `-r/--rules <dir>` (defaults to `rules/`), `-g/--golden
<path>` to suppress matches also present in a clean baseline, and
`-o/--output <file>` to write findings as JSON.

**6. Manual firmware extraction** — use this when you need an extracted
directory for standalone `filesystem.py` testing (command 3), or to inspect
Binwalk's output by hand:

```python
from pathlib import Path
from modules import binwalk_wrapper

result = binwalk_wrapper.extract('<firmware-path>', Path('<output-dir>'))
print('Extracted to:', result.extracted_dir)
```

> **Note:** the `output_dir` argument is accepted for interface
> compatibility but the subprocess backend ignores it — Binwalk always
> extracts to its own fixed `_<firmware_filename>.extracted` directory
> (next to the firmware file, or in the current working directory if the
> firmware lies outside it). Always use `result.extracted_dir` for the
> real location rather than assuming it's what you passed in. This
> command does **not** auto-cleanup like the full pipeline does — delete
> the extracted directory yourself when you're done with it.

**7. Run the automated test suite** — run this after any code change before
considering it done.

```bash
python3 -m pytest tests/ -v
```

**8. Check latest outputs** — lists the most recently generated reports and
plots (`main.py` writes a timestamped `report_*.json` and `entropy_*.png` per
run into `output/`).

```bash
ls -lt output/ | head -5
```

### Standard Testing Workflow — Comparing Clean vs Trojaned Firmware

A repeatable recipe for validating detection against a clean/trojaned
firmware pair:

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

Compare the summary lines from steps 3 and 4 side by side. A healthy result
shows the trojaned firmware's finding count and severity breakdown close to
the clean baseline, with a small number of additional findings tracing to
the actual injected content. A large, unexplained discrepancy between the
two — especially the clean firmware showing *more* findings than the
trojaned one — indicates a bug, not a detection success. This exact pattern
(97 HIGH findings on clean vs. 5 on trojaned, from the same underlying
regions) caught a real false-positive/non-determinism bug during
development; see commit `31272fa` ("Fix entropy false-positive/
non-determinism") for the root cause and fix.

### Known Limitations — Entropy Detection

Shannon entropy on small windows (256 bytes) has statistical bias: true
random data (`os.urandom()`) averages **~7.17 bits/byte** in a 256-byte
window, not 8.0, due to small-sample variance (256 draws over 256 possible
byte values collide often enough to pull the estimate well below the
theoretical maximum). This means a well-padded or statistically-tuned
malicious payload can produce entropy similar to the firmware's own
legitimate compressed regions (which often sit in the 7.0–7.5 range for the
same reason), potentially evading pure entropy-based detection — this is
most pronounced on firmware that is *already* densely compressed
(squashfs/LZMA/XZ) end to end, where there's no low-entropy neighborhood
left for an injected payload to contrast against either.

This is why HexWarden treats entropy as one signal among several — not the
sole detector — and why golden-image diffing (Mode A) exists as an
independent detection layer: diff-based detection compares actual bytes
against a known-clean reference and does not depend on entropy thresholds
at all. **When a clean reference is available, prefer golden-image diff**
(command 2 above) for the strongest detection guarantee.

### Test Firmware Generation

To build a synthetic trojaned firmware for testing, append a payload
combining:

1. A high-entropy blob for entropy/golden-diff testing — note that
   `os.urandom()` may not read as high-entropy at small window sizes (see
   [Known Limitations](#known-limitations--entropy-detection) above);
   prefer a byte-permutation-based blob (e.g. `bytes(range(256)) * N`,
   which gives every 256-byte window exactly one of each byte value, a
   deterministic peak entropy of 8.0) for reliable entropy-detection
   testing.
2. Suspicious ASCII strings (fake C2 IPs, shell commands, credentials) for
   YARA/string-matching testing.
3. Known cryptographic constants (e.g. AES S-box bytes) for
   crypto-signature testing.

See `tests/test_firmware_pipeline.py`'s `_MAX_ENTROPY_BLOB` for the exact
byte-permutation-blob pattern used by the automated test suite, which
correctly avoids the `os.urandom()` small-window bias described above.

