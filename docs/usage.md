# Usage

> TODO: expand with full CLI examples as more modules land.

## Installation

```bash
pip install -r requirements.txt
pip install .
```

## Running the CLI

`--modules` defaults to `pipeline`, which runs entropy analysis plus
recursive Binwalk extraction. Pass `--modules entropy` for a raw-binary-only
scan with no extraction step.

```bash
hexwarden --firmware path/to/firmware.bin --modules pipeline --output output/ --verbose
```

Or without installing:

```bash
python main.py --firmware path/to/firmware.bin
```

### A note on Binwalk

The extraction pipeline drives Binwalk through its Python API
(`import binwalk`), not the CLI. That API ships only with the classic,
long-unmaintained Python implementation of Binwalk -- not with the modern
Rust rewrite most systems now install as the `binwalk` command (which has
no Python bindings at all). If a working `import binwalk` is not available,
`modules/binwalk_wrapper.py` raises a clear error internally and
`modules/firmware_pipeline.py` catches it, logs a warning, and falls back
to raw-binary entropy findings only -- extraction is a best-effort layer,
never a hard dependency for getting a scan result.

## Running a single module standalone

Every module is independently runnable, e.g.:

```bash
python -m modules.entropy path/to/firmware.bin
python -m modules.binwalk_wrapper path/to/firmware.bin
python -m modules.firmware_pipeline path/to/firmware.bin
```
