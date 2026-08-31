"""Analysis modules package for HexWarden.

Each submodule implements the shared `analyze(filepath: str) -> List[Finding]`
interface contract defined in `core`. Submodules are safe to import with no
side effects and never print directly to stdout; all output is returned as
`Finding` objects.

Inputs:
    None (this file defines package metadata only).

Outputs:
    None.
"""
