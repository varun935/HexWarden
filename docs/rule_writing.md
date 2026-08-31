# Writing YARA Rules

> TODO: expand this guide once `modules/yara_engine.py` is implemented.

## Where rules live

Place new `.yar` files under the matching category in `rules/` (see `rules/README.md` for the
category list). One file may contain multiple related rules.

## Required meta fields

Every rule should declare:

```yara
meta:
    description = "Human-readable explanation of what this rule detects"
    severity = "low" | "medium" | "high" | "critical"
    author = "your name or handle"
```

`modules/yara_engine.py` will read `severity` to build the corresponding `Finding.severity` and
`Finding.score` (via `config.SEVERITY_SCORE_WEIGHTS`).

## Testing a rule

```bash
yara rules/<category>/<file>.yar path/to/firmware.bin
```
