# Architecture

> TODO: expand this document as `core/pipeline.py` and `core/scoring.py` are implemented.

## Overview

HexWarden analyzes firmware images through three layers:

1. **Static analysis** — `modules/entropy.py`, `strings.py`, `imports.py`, `yara_engine.py`, `crypto_constants.py`, `filesystem.py`.
2. **Dynamic analysis** — `modules/dynamic/network_monitor.py`, `modules/dynamic/syscall_tracer.py`.
3. **Side-channel correlation** — TODO.

## Pipeline

`core/pipeline.py` will orchestrate the enabled modules (see `config.ENABLED_MODULES`) and pass
their combined `Finding` list to `core/scoring.py`, which produces a single risk score and verdict.

Currently, `main.py` invokes implemented modules directly; only `modules/entropy.py` is implemented.
