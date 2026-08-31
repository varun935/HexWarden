"""Risk scoring and verdict aggregation for HexWarden.

Not yet implemented. Will combine a list of `Finding` objects into a
single 0-100 risk score (using `config.SEVERITY_SCORE_WEIGHTS`) and a
verdict string ("clean", "suspicious", "malicious") using
`config.RISK_VERDICT_SUSPICIOUS_THRESHOLD` and
`config.RISK_VERDICT_MALICIOUS_THRESHOLD`. Scaffolded now to establish the
package structure; the aggregation logic lands in a follow-up change.

Inputs:
    findings (List[Finding]): Findings collected from one or more
        analysis modules.

Outputs:
    Tuple[int, str]: Combined risk score and verdict (currently always
    raises NotImplementedError until this module is implemented).
"""

from typing import List, Tuple

from core import Finding


def aggregate(findings: List[Finding]) -> Tuple[int, str]:
    """Aggregate findings into a combined risk score and verdict.

    Args:
        findings: Findings collected from one or more analysis modules.

    Returns:
        Tuple of (risk_score, verdict), where risk_score is 0-100 and
        verdict is one of "clean", "suspicious", "malicious".

    Raises:
        NotImplementedError: Always, until this module is implemented.
    """
    raise NotImplementedError("Risk score aggregation is not implemented yet.")
