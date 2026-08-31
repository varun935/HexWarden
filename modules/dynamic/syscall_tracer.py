"""Syscall tracing module for HexWarden.

Not yet implemented. Will capture and analyze syscall traces (via strace
or eBPF) produced by firmware running in an emulator/sandbox, flagging
suspicious syscall sequences such as unexpected file writes, process
spawning, or privilege escalation attempts. Scaffolded now to establish
the package structure and the shared `analyze()` interface contract; the
tracing/analysis logic lands in a follow-up change.

Inputs:
    filepath (str): Path to a syscall trace log file to analyze.

Outputs:
    List[Finding]: Analysis findings (currently always raises
    AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding

MODULE_NAME = "syscall_tracer"


def analyze(filepath: str) -> List[Finding]:
    """Analyze a syscall trace for suspicious behavior (not yet implemented).

    Args:
        filepath: Absolute or relative path to a syscall trace log file.

    Returns:
        List of Finding objects.

    Raises:
        FileNotFoundError: If the trace file does not exist.
        AnalysisError: Always, until this module is implemented.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Trace file not found: {filepath}")

    raise AnalysisError(f"Module '{MODULE_NAME}' is not implemented yet.")
