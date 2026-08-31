"""ELF import/symbol analysis module for HexWarden.

Not yet implemented. Will parse ELF firmware images (via pyelftools) to
inspect imported symbols and flag suspicious combinations (e.g. raw socket
APIs, ptrace, exec-family calls) that are unusual for embedded firmware.
Scaffolded now to establish the package structure and the shared
`analyze()` interface contract; the parsing logic lands in a follow-up
change.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Analysis findings (currently always raises
    AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding

MODULE_NAME = "imports"


def analyze(filepath: str) -> List[Finding]:
    """Analyze ELF imports/symbols in firmware (not yet implemented).

    Args:
        filepath: Absolute or relative path to firmware binary.

    Returns:
        List of Finding objects.

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: Always, until this module is implemented.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")

    raise AnalysisError(f"Module '{MODULE_NAME}' is not implemented yet.")
