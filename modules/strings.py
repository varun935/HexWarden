"""String extraction and pattern-matching module for HexWarden.

Not yet implemented. Will extract printable ASCII/UTF-16 strings from a
firmware image and flag ones matching suspicious patterns (hardcoded
credentials, C2-style URLs/IPs, shell commands, debug backdoors). Scaffolded
now to establish the package structure and the shared `analyze()` interface
contract; the extraction/matching logic lands in a follow-up change.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Analysis findings (currently always raises
    AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding

MODULE_NAME = "strings"


def analyze(filepath: str) -> List[Finding]:
    """Extract and pattern-match strings in firmware (not yet implemented).

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
