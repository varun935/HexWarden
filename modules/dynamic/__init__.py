"""Dynamic analysis submodules for HexWarden.

Contains modules that observe firmware behavior at runtime (in an
emulator or on hardware) rather than analyzing the static image, such as
network traffic capture and syscall tracing. Submodules here follow the
same `analyze(filepath: str) -> List[Finding]` contract as static modules,
where `filepath` typically refers to a capture/trace artifact rather than
the raw firmware binary.

Inputs:
    None (this file defines package metadata only).

Outputs:
    None.
"""
