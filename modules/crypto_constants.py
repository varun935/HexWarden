"""Cryptographic constant detection module for HexWarden.

Not yet implemented. Will scan firmware for well-known cryptographic
constants (AES S-boxes, SHA/MD5 initialization vectors, CRC polynomial
tables) whose unexplained presence can indicate custom encryption used to
hide a payload or exfiltrate data. Scaffolded now to establish the package
structure and the shared `analyze()` interface contract; the detection
logic lands in a follow-up change.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Analysis findings (currently always raises
    AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding

MODULE_NAME = "crypto_constants"


def analyze(filepath: str) -> List[Finding]:
    """Detect known crypto constants in firmware (not yet implemented).

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
