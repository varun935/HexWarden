"""Core package for the HexWarden firmware analysis toolkit.

Defines the shared `Finding` data structure returned by every analysis
module, plus the `AnalysisError` exception raised when a module fails to
complete analysis of a firmware image.

Inputs:
    None directly; this package is consumed by every module under
    `modules/` and by `core/pipeline.py` and `core/scoring.py`.

Outputs:
    Finding: dataclass representing a single analysis finding.
    AnalysisError: exception type raised on recoverable analysis failure.
"""

from dataclasses import dataclass, field
from typing import Optional


class AnalysisError(Exception):
    """Raised when an analysis module fails to complete successfully.

    This is distinct from `FileNotFoundError`, which signals that the
    input file itself is missing. `AnalysisError` signals that the file
    was found but could not be analyzed (e.g. corrupted data, an
    unsupported format, or an internal tool failure).
    """


@dataclass
class Finding:
    """A single finding produced by an analysis module.

    Attributes:
        module_name: Name of the module that produced this finding
            (e.g. "entropy").
        severity: One of "low", "medium", "high", "critical".
        offset: Byte offset in the firmware where the finding was
            located, or None if not applicable.
        description: Human-readable explanation of the finding.
        evidence: The actual bytes/string/value that triggered the
            finding, rendered as a string.
        score: Risk contribution of this finding, from 0 to 100.
        raw: Extra module-specific data (e.g. region boundaries).
    """

    module_name: str
    severity: str
    offset: Optional[int]
    description: str
    evidence: str
    score: int
    raw: dict = field(default_factory=dict)
