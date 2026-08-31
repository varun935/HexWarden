"""Filesystem anomaly scanner module for HexWarden.

Not yet implemented. Will mount/extract embedded filesystem images
(SquashFS, JFFS2, CramFS, etc.) from firmware and flag anomalies such as
unexpected setuid binaries, hidden init scripts, or files with suspicious
timestamps. Scaffolded now to establish the package structure and the
shared `analyze()` interface contract; the extraction/scanning logic lands
in a follow-up change.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Analysis findings (currently always raises
    AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding

MODULE_NAME = "filesystem"


def analyze(filepath: str) -> List[Finding]:
    """Scan an embedded filesystem for anomalies (not yet implemented).

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
