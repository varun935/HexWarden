"""Analysis pipeline orchestration for HexWarden.

Not yet implemented. Will run enabled `modules/*` analyzers against a
firmware image (in parallel, per `config.ENABLED_MODULES`) and merge their
findings into a single list for `core/scoring.py` to aggregate.
Scaffolded now to establish the package structure; `main.py` currently
invokes modules directly until this orchestration layer is built out.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Combined findings from all enabled modules (currently
    always raises AnalysisError until this module is implemented).
"""

from pathlib import Path
from typing import List

from core import AnalysisError, Finding


def run_pipeline(filepath: str) -> List[Finding]:
    """Run all enabled analysis modules against a firmware image.

    Args:
        filepath: Absolute or relative path to firmware binary.

    Returns:
        Combined list of Finding objects from every enabled module.

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: Always, until this module is implemented.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")

    raise AnalysisError("Pipeline orchestration is not implemented yet.")
