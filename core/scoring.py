"""Risk scoring and verdict aggregation for HexWarden.

Combines findings from every analysis module that ran into one weighted
verdict. No module's findings are a verdict on their own -- this is
where cross-module corroboration and severity weighting turn a pile of
candidates into a single risk picture.

Corroboration: two or more *different* modules independently flagging
the same byte region (within `CORROBORATION_WINDOW_BYTES`) is a much
stronger signal than either finding alone, so each finding in such a
cluster has its weighted contribution boosted by `CORROBORATION_BONUS`.
Findings with no byte offset (e.g. modules/filesystem.py's checks, which
are file-path-based, not offset-based) cannot participate -- there's no
byte region to compare.

Inputs:
    findings (List[Finding]): Findings collected from one or more
        analysis modules, typically the combined output of a full
        pipeline run.
    modules_run (Optional[List[str]]): Which modules were actually
        invoked this scan -- confidence is `len(modules_run) /
        len(MODULE_WEIGHTS)`, i.e. what fraction of the full detection
        registry actually checked this firmware (a module that ran and
        found nothing still counts; it's a passed check, not missing
        evidence). Pass this explicitly whenever golden_diff/
        network_monitor are conditionally skipped (no golden reference/
        pcap provided) so confidence isn't silently inflated as if they
        ran. Defaults to every module in MODULE_WEIGHTS when not given,
        i.e. "assume a full pipeline ran" -- the one-argument
        `score(findings)` call the task's interface specifies still
        works standalone.

Outputs:
    ScanScore: Combined weighted score, verdict, per-module breakdown,
    top findings, and corroborated-region findings.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

import config
from core import Finding

# Per-module, per-severity weight. A CRITICAL from a module that diffs
# against a known-clean reference (golden_diff) is worth more than a
# CRITICAL from a purely heuristic pass (strings) -- these are not the
# same as config.SEVERITY_SCORE_WEIGHTS, which is a single module-agnostic
# scale used internally by each module for its own Finding.score.
MODULE_WEIGHTS: Dict[str, Dict[str, int]] = {
    "yara_engine": {"critical": 90, "high": 65, "medium": 35, "low": 5},
    "yara_engine_raw": {"critical": 90, "high": 65, "medium": 35, "low": 5},
    "filesystem": {"critical": 80, "high": 60, "medium": 30, "low": 5},
    "golden_diff": {"critical": 85, "high": 65, "medium": 35, "low": 5},
    "firmware_pipeline": {"critical": 70, "high": 50, "medium": 20, "low": 3},
    "firmware_pipeline_extracted": {"critical": 65, "high": 45, "medium": 15, "low": 2},
    "strings": {"critical": 60, "high": 40, "medium": 15, "low": 2},
    "strings_raw": {"critical": 60, "high": 40, "medium": 15, "low": 2},
    "network_monitor": {"critical": 75, "high": 55, "medium": 25, "low": 5},
}

CORROBORATION_WINDOW_BYTES = 4096
CORROBORATION_BONUS = 0.20  # +20% contribution for findings in a corroborated cluster

TOP_FINDINGS_COUNT = 5

# (floor, verdict, color) -- checked highest-first, first match wins.
_VERDICT_BANDS = [
    (76, "CRITICAL", "red"),
    (51, "HIGH", "orange"),
    (26, "MEDIUM", "yellow"),
    (0, "LOW", "green"),
]


@dataclass
class ScanScore:
    """Combined weighted verdict over every finding from one scan.

    Attributes:
        total_score: Normalized 0-100 display score --
            `min(100, int(raw_weighted_sum / config.SCORING_EXPECTED_MAX * 100))`.
            The raw, uncapped weighted sum (MODULE_WEIGHTS contributions,
            post-corroboration bonus) is an internal computation detail,
            not exposed on this dataclass -- `config.SCORING_EXPECTED_MAX`
            is "how much raw weighted signal is unambiguously Critical".
        verdict: "LOW", "MEDIUM", "HIGH", or "CRITICAL" -- derived from
            the normalized `total_score`.
        verdict_color: "green", "yellow", "orange", or "red" -- matches
            `verdict`, for direct use as a CSS class/token.
        confidence: Fraction (0.0-1.0) of the full `MODULE_WEIGHTS`
            registry that `modules_run` actually invoked this scan --
            NOT the fraction that produced findings. A module that ran
            and found nothing is a positive signal (the firmware passed
            that check), not an absence of evidence, so it must not
            depress confidence.
        module_scores: Per-module weighted score sum (post-corroboration
            bonus).
        module_finding_counts: Per-module severity histogram, e.g.
            {"yara_engine": {"critical": 1, "high": 0, "medium": 2, "low": 0}}.
        top_findings: Up to `TOP_FINDINGS_COUNT` findings with the
            highest individual `Finding.score`, descending.
        corroborated_findings: Findings that share a byte region (within
            `CORROBORATION_WINDOW_BYTES`) with a finding from a
            *different* module, sorted by offset.
        summary: One human-readable sentence describing the verdict.
    """

    total_score: int
    verdict: str
    verdict_color: str
    confidence: float
    module_scores: Dict[str, int] = field(default_factory=dict)
    module_finding_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    top_findings: List[Finding] = field(default_factory=list)
    corroborated_findings: List[Finding] = field(default_factory=list)
    summary: str = ""


def _verdict_for_score(display_score: int) -> tuple:
    """Map a normalized 0-100 display score to (verdict, color).

    Args:
        display_score: Normalized score (see `ScanScore.total_score`),
            not the raw weighted sum.

    Returns:
        (verdict, verdict_color) tuple.

    Raises:
        None.
    """
    for floor, verdict, color in _VERDICT_BANDS:
        if display_score >= floor:
            return verdict, color
    return "LOW", "green"  # unreachable given a 0 floor, kept as a defensive fallback


def _corroborated_clusters(findings: List[Finding]) -> List[List[Finding]]:
    """Group findings into proximity clusters and keep only multi-module ones.

    Args:
        findings: All findings (any module).

    Returns:
        List of clusters (each a list of Finding), one per group of
        findings within `CORROBORATION_WINDOW_BYTES` of each other that
        includes findings from 2+ distinct modules. Findings with
        `offset is None` are excluded -- there's no byte region to
        compare them by.

    Raises:
        None.
    """
    offset_findings = sorted(
        (f for f in findings if f.offset is not None), key=lambda f: f.offset
    )
    if not offset_findings:
        return []

    clusters: List[List[Finding]] = []
    current = [offset_findings[0]]
    current_max_offset = offset_findings[0].offset
    for finding in offset_findings[1:]:
        if finding.offset - current_max_offset <= CORROBORATION_WINDOW_BYTES:
            current.append(finding)
            current_max_offset = max(current_max_offset, finding.offset)
        else:
            clusters.append(current)
            current = [finding]
            current_max_offset = finding.offset
    clusters.append(current)

    return [
        cluster
        for cluster in clusters
        if len({f.module_name for f in cluster}) >= 2
    ]


def _weight_for(finding: Finding) -> int:
    """Look up a finding's module-and-severity weight.

    Args:
        finding: The finding to weight.

    Returns:
        `MODULE_WEIGHTS[finding.module_name][finding.severity]`, falling
        back to `config.SEVERITY_SCORE_WEIGHTS[finding.severity]` for a
        module not in the registry (keeps scoring functional rather than
        crashing if a new module is added before its weights are).

    Raises:
        None.
    """
    module_weights = MODULE_WEIGHTS.get(finding.module_name)
    if module_weights is not None and finding.severity in module_weights:
        return module_weights[finding.severity]
    return config.SEVERITY_SCORE_WEIGHTS.get(finding.severity, 0)


def _build_summary(display_score: int, modules_with_findings: int) -> str:
    """Build the one-sentence human-readable verdict summary.

    Args:
        display_score: Normalized 0-100 score (see `ScanScore.total_score`).
        modules_with_findings: Count of distinct modules that produced at
            least one finding -- used only in the CRITICAL branch, to
            name how many independent detection layers corroborate the
            verdict.

    Returns:
        A one-sentence summary, banded on the same 0-100 scale as the
        verdict thresholds (<=25 LOW, <=50 MEDIUM, <=75 HIGH, else
        CRITICAL).

    Raises:
        None.
    """
    if display_score <= 25:
        return "No significant threats detected -- firmware appears clean across all detection layers."
    if display_score <= 50:
        return "Some anomalies detected -- manual review recommended but no confirmed malicious indicators."
    if display_score <= 75:
        return "Multiple suspicious indicators found -- firmware should be inspected before deployment."
    return (
        f"Critical: strong evidence of embedded malware across "
        f"{modules_with_findings} independent detection layer(s). Do not deploy."
    )


def score(findings: List[Finding], modules_run: Optional[List[str]] = None) -> ScanScore:
    """Combine findings from all modules into one weighted verdict.

    Args:
        findings: Findings collected from one or more analysis modules.
        modules_run: Which modules were actually invoked this scan.
            Defaults to every module in `MODULE_WEIGHTS` (i.e. assumes a
            full pipeline ran) when not given.

    Returns:
        A `ScanScore` combining every finding into one verdict.

    Raises:
        None.
    """
    if modules_run is None:
        modules_run = list(MODULE_WEIGHTS.keys())

    corroborated_clusters = _corroborated_clusters(findings)
    corroborated_ids = {id(f) for cluster in corroborated_clusters for f in cluster}

    raw_score = 0
    module_scores: Dict[str, int] = {}
    module_finding_counts: Dict[str, Dict[str, int]] = {}

    for finding in findings:
        contribution = _weight_for(finding)
        if id(finding) in corroborated_ids:
            contribution = round(contribution * (1 + CORROBORATION_BONUS))

        raw_score += contribution
        module_scores[finding.module_name] = module_scores.get(finding.module_name, 0) + contribution

        counts = module_finding_counts.setdefault(
            finding.module_name, {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        )
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    display_score = min(100, int(raw_score / config.SCORING_EXPECTED_MAX * 100))
    verdict, verdict_color = _verdict_for_score(display_score)

    # "Modules that ran" (positive signal -- a module that ran and found
    # nothing means the firmware passed that check) drives confidence.
    # "Modules that found something" is a different metric, kept
    # separately for the CRITICAL summary sentence's "independent
    # detection layers" count -- conflating the two was the original bug.
    confidence = min(1.0, len(modules_run) / len(MODULE_WEIGHTS)) if MODULE_WEIGHTS else 0.0
    modules_with_findings = len(module_scores)

    top_findings = sorted(findings, key=lambda f: f.score, reverse=True)[:TOP_FINDINGS_COUNT]

    corroborated_findings = sorted(
        (f for cluster in corroborated_clusters for f in cluster), key=lambda f: f.offset
    )

    summary = _build_summary(display_score, modules_with_findings)

    return ScanScore(
        total_score=display_score,
        verdict=verdict,
        verdict_color=verdict_color,
        confidence=confidence,
        module_scores=module_scores,
        module_finding_counts=module_finding_counts,
        top_findings=top_findings,
        corroborated_findings=corroborated_findings,
        summary=summary,
    )
