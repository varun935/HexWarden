"""Context-aware entropy + recursive Binwalk extraction pipeline for HexWarden.

Detection philosophy: entropy is a witness that flags candidates, not a
judge that issues verdicts. A global entropy threshold cannot tell
legitimate high entropy (a compressed blob, a filesystem image, compiled
code) apart from malicious high entropy (an injected, encrypted payload)
-- so this pipeline never reports a high-entropy region on entropy value
alone. A region only becomes a Finding if it is anomalous IN CONTEXT:

    1. Run a Binwalk scan on the file (raw firmware binary, then
       recursively for every file Binwalk extracts from it).
    2. Run entropy analysis on the file's raw bytes, unconditionally --
       Binwalk's result only ever changes a region's label, never
       whether entropy runs.
    3. Local contrast: measure each entropy sample against its own local
       neighborhood (median + IQR, robust to outliers). Only a sample
       that stands out from its neighborhood -- not merely one that
       exceeds a fixed global threshold -- is a local anomaly. A
       7.9-entropy sample inside a 7.8-entropy compressed blob is
       unremarkable; the same value in the middle of 5.5-entropy code is
       a real outlier.
    4. Format-consistency drop: a local-anomaly region whose offset
       overlaps a Binwalk-recognized format, with peak entropy inside
       that format's expected range (`config.FORMAT_ENTROPY_RANGES`), is
       DROPPED -- no Finding object is created for it at all. A region
       whose entropy falls outside the expected range is a genuine
       "format anomaly" and still becomes a Finding.
    5. Global whole-file check, independent of local contrast: a file
       with no internal contrast because it is uniformly encrypted
       throughout would never stand out locally, so each file's overall
       median entropy is checked too -- uniformly high with no Binwalk
       format explanation at all is itself a candidate.
    6. Every surviving candidate is scored, not just flagged: a sharp
       entropy transition (spike-and-return, not gradual drift), a
       byte-distribution chi-square test (near-uniform reads as
       encryption-like, structured reads as compression-like), and
       region size (a payload-sized region is weighted up; a tiny or huge
       one is weighted down, but size never drops a finding outright) are
       combined into a single confidence score, which determines severity.
    7. Binwalk's matryoshka mode already extracted every nested file's
       contents in one recursive pass, so a single walk of the final
       extracted directory tree -- applying steps 1-6 to every file in it,
       up to `config.EXTRACTED_MAX_DEPTH` levels deep -- is equivalent to
       repeating steps 1-7 at each nesting level.
    8. As soon as that extraction is on disk (and before it is walked for
       entropy), `modules/filesystem.py` runs its own independent checks
       against the same extracted tree -- no second extraction -- looking
       for backdoor accounts, suspicious persistence, and misplaced
       executables. Its findings (module_name="filesystem") merge into
       the same combined list; a failure there is logged and does not
       abort the rest of the pipeline.

The findings list contains only anomaly candidates: format-consistent
regions dropped in step 4 never appear. Aggregate counts (regions
analyzed, dropped, local-anomaly candidates, whole-file anomalies) are
tracked separately in an `EntropySummary` and logged, not folded into the
findings list.

The entire extracted directory tree is deleted (`shutil.rmtree`) before
`run_pipeline()` returns, whether analysis succeeded or raised -- cleanup
runs in a `finally` block. The original firmware file and the configured
output directory are never touched by cleanup.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: Candidate findings from the raw-binary entropy scan
    (module_name="firmware_pipeline"), an unconditional raw-binary YARA
    pass (module_name="yara_engine_raw") and strings pass
    (module_name="strings_raw") that run regardless of whether Binwalk
    extraction produced anything, the extracted-file entropy walk
    (module_name="firmware_pipeline_extracted"), and the filesystem
    checks (module_name="filesystem"). As a side effect, a combined
    entropy plot is written under the configured output directory
    (before the extracted directory tree is cleaned up).
"""

import logging
import shutil
import statistics
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config
from core import AnalysisError, Finding
from modules import binwalk_wrapper, entropy, filesystem, strings, yara_engine
from modules.binwalk_wrapper import BinwalkRegion, BinwalkResult

logger = logging.getLogger(__name__)

MODULE_NAME = "firmware_pipeline"
EXTRACTED_MODULE_NAME = "firmware_pipeline_extracted"
YARA_RAW_MODULE_NAME = "yara_engine_raw"
STRINGS_RAW_MODULE_NAME = "strings_raw"

# Rules directory for the raw-binary YARA pass -- same location
# web/app.py's dashboard pipeline uses for its own (extracted-file-scoped)
# YaraEngine instance.
_YARA_RULES_DIR = config.PROJECT_ROOT / "rules"

# A (start, end, keyword, description, expected_min, expected_max) tuple
# describing one Binwalk region matched against config.FORMAT_ENTROPY_RANGES,
# with an inferred byte extent.
_RegionExtent = Tuple[int, int, str, str, float, float]


@dataclass
class EntropySummary:
    """Aggregate counts for the pipeline's context-aware entropy analysis.

    Attributes:
        regions_analyzed: Total local-anomaly regions considered (the sum
            of `dropped_format_consistent` and `local_anomaly_candidates`).
        dropped_format_consistent: Regions whose entropy was consistent
            with a Binwalk-recognized format's expected range -- dropped,
            never became a Finding.
        local_anomaly_candidates: Regions that stood out from their local
            neighborhood and were not format-consistent -- real findings.
        whole_file_anomalies: Files flagged by the independent whole-file
            check (uniformly high entropy, no format explanation at all).
    """

    regions_analyzed: int = 0
    dropped_format_consistent: int = 0
    local_anomaly_candidates: int = 0
    whole_file_anomalies: int = 0

    def merge(self, other: "EntropySummary") -> None:
        """Add another summary's counts into this one, in place.

        Args:
            other: Summary to merge in.

        Returns:
            None.

        Raises:
            None.
        """
        self.regions_analyzed += other.regions_analyzed
        self.dropped_format_consistent += other.dropped_format_consistent
        self.local_anomaly_candidates += other.local_anomaly_candidates
        self.whole_file_anomalies += other.whole_file_anomalies

    def as_dict(self) -> Dict[str, int]:
        """Render as a plain dict, for passing to `entropy.generate_pipeline_plot()`.

        Returns:
            Dict with the same four fields as this dataclass.

        Raises:
            None.
        """
        return {
            "regions_analyzed": self.regions_analyzed,
            "dropped_format_consistent": self.dropped_format_consistent,
            "local_anomaly_candidates": self.local_anomaly_candidates,
            "whole_file_anomalies": self.whole_file_anomalies,
        }


@dataclass
class _CandidateRegion:
    """One merged, contiguous local-anomaly region, ready to be scored.

    Attributes:
        start_offset: Byte offset where the region begins.
        end_offset: Byte offset where the region ends (exclusive).
        peak_entropy: Highest entropy sample within the region.
        neighborhood_median: The peak sample's local neighborhood median.
        neighborhood_iqr: The peak sample's local neighborhood IQR.
        transition_anomaly: True if any sample in the region sits inside
            a detected sharp entropy spike-and-return.
    """

    start_offset: int
    end_offset: int
    peak_entropy: float
    neighborhood_median: float
    neighborhood_iqr: float
    transition_anomaly: bool


def _hex(offset: int) -> str:
    """Format a byte offset as an uppercase hex string, e.g. "0xF11D30".

    Args:
        offset: Byte offset to format.

    Returns:
        The hex-formatted string.

    Raises:
        None.
    """
    return f"0x{offset:X}"


def _match_format_keyword(description: str) -> Optional[Tuple[str, float, float]]:
    """Match a Binwalk description against `config.FORMAT_ENTROPY_RANGES`.

    Args:
        description: Binwalk's human-readable identification string.

    Returns:
        A (keyword, expected_min, expected_max) tuple for the first
        matching keyword found (in `config.FORMAT_ENTROPY_RANGES`
        iteration order), or None if no keyword appears in `description`.

    Raises:
        None.
    """
    lowered = description.lower()
    for keyword, entropy_range in config.FORMAT_ENTROPY_RANGES.items():
        if keyword in lowered:
            return keyword, entropy_range[0], entropy_range[1]
    return None


def _recognized_format_extents(known_regions: List[BinwalkRegion]) -> List[_RegionExtent]:
    """Filter Binwalk regions to ones matching a known format, with inferred extents.

    A region's own `size` is used directly when Binwalk reported one.
    Binwalk's plain-text scan table (the subprocess backend currently in
    use) never does, so in practice an end offset is inferred instead, as
    the start of the next format-matching region in offset order; the
    last (highest-offset) region with no reported size uses
    `config.BINWALK_LAST_REGION_SIZE_ESTIMATE` as a safe default extent.
    Regions whose description does not match any `config.FORMAT_ENTROPY_RANGES`
    keyword are excluded entirely -- they carry no entropy expectation to
    cross-reference against.

    Args:
        known_regions: Regions Binwalk identified in a file.

    Returns:
        List of `_RegionExtent` tuples, sorted by start offset.

    Raises:
        None.
    """
    matched: List[Tuple[int, Optional[int], str, str, float, float]] = []
    for region in known_regions:
        match = _match_format_keyword(region.description)
        if match is None:
            continue
        keyword, expected_min, expected_max = match
        matched.append(
            (region.offset, region.size, keyword, region.description, expected_min, expected_max)
        )

    matched.sort(key=lambda item: item[0])

    extents: List[_RegionExtent] = []
    for index, (start, size, keyword, description, expected_min, expected_max) in enumerate(matched):
        if size is not None:
            end = start + size
        elif index + 1 < len(matched):
            end = matched[index + 1][0]
        else:
            end = start + config.BINWALK_LAST_REGION_SIZE_ESTIMATE
        extents.append((start, end, keyword, description, expected_min, expected_max))
    return extents


def _find_overlap(start: int, end: int, extents: List[_RegionExtent]) -> Optional[_RegionExtent]:
    """Find the first region extent overlapping a byte range.

    Args:
        start: Start offset of the byte range to check.
        end: End offset of the byte range to check.
        extents: Region extents as built by `_recognized_format_extents`.

    Returns:
        The first overlapping `_RegionExtent`, using the standard
        half-open interval overlap test (`region_start < end and start <
        region_end`) -- which, unlike checking only whether either range's
        *start* falls inside the other, also catches a candidate region
        that fully contains a format's extent (a local-anomaly region is
        often wider than the exact signature match it surrounds, e.g. a
        few samples of gradual rise/fall on each side) -- or None if none
        overlap.

    Raises:
        None.
    """
    for extent in extents:
        region_start, region_end = extent[0], extent[1]
        if region_start < end and start < region_end:
            return extent
    return None


def _relative_location(filepath: Path, extraction_root: Path) -> str:
    """Render a file's path relative to the extraction root, POSIX-style with a leading slash.

    Args:
        filepath: Path to the extracted file.
        extraction_root: Root directory the file was extracted under.

    Returns:
        A string like "/etc/config/foo".

    Raises:
        None.
    """
    try:
        relative = filepath.relative_to(extraction_root)
    except ValueError:
        relative = filepath
    return "/" + relative.as_posix()


def _location_phrase(
    source: str, start_offset: int, extracted_relative_location: Optional[str]
) -> str:
    """Build the human-readable location clause used in finding descriptions.

    Args:
        source: "raw_binary" or "extracted".
        start_offset: Byte offset the region/file starts at.
        extracted_relative_location: The file's location relative to the
            extraction root (see `_relative_location`), or None for the
            raw firmware binary.

    Returns:
        e.g. "at offset 0xF11D30" for the raw binary, or
        "at offset 0x0 in /bin/busybox" for an extracted file.

    Raises:
        None.
    """
    if source == "raw_binary":
        return f"at offset {_hex(start_offset)}"
    return f"at offset {_hex(start_offset)} in {extracted_relative_location}"


def _categorize_size(size_bytes: int) -> str:
    """Categorize a candidate region's size for confidence weighting.

    Args:
        size_bytes: Size of the region in bytes.

    Returns:
        "payload-sized" if within [`config.ENTROPY_PAYLOAD_SIZE_MIN`,
        `config.ENTROPY_PAYLOAD_SIZE_MAX`] -- the size range real
        injected payloads live in; "small" if smaller (likely a
        hash/key/padding); "large" if bigger (likely a legitimate blob).

    Raises:
        None.
    """
    if size_bytes < config.ENTROPY_PAYLOAD_SIZE_MIN:
        return "small"
    if size_bytes > config.ENTROPY_PAYLOAD_SIZE_MAX:
        return "large"
    return "payload-sized"


def _classify_distribution(chi_square: float) -> str:
    """Classify a chi-square uniformity statistic into a distribution type.

    Args:
        chi_square: Result of `entropy.chi_square_uniformity()`.

    Returns:
        "encryption-like" below `config.CHI_SQUARE_ENCRYPTED_THRESHOLD`
        (near-perfectly uniform byte distribution); "structured" at or
        above `config.CHI_SQUARE_ENCRYPTED_THRESHOLD *
        config.CHI_SQUARE_STRUCTURED_MULTIPLIER` (strongly patterned,
        not really random/compressed at all); "compression-like" in
        between (uniform-ish but with the residual structure typical of
        compressed data).

    Raises:
        None.
    """
    if chi_square < config.CHI_SQUARE_ENCRYPTED_THRESHOLD:
        return "encryption-like"
    if chi_square < config.CHI_SQUARE_ENCRYPTED_THRESHOLD * config.CHI_SQUARE_STRUCTURED_MULTIPLIER:
        return "compression-like"
    return "structured"


def _compute_confidence(
    base: float, transition_anomaly: bool, distribution_type: str, size_category: str
) -> float:
    """Combine corroborating signals into a single confidence score.

    Args:
        base: Starting confidence -- `config.CONFIDENCE_LOCAL_ANOMALY_BASE`
            for a local-anomaly candidate, `config.CONFIDENCE_WHOLE_FILE_BASE`
            for a whole-file candidate.
        transition_anomaly: True if a sharp spike-and-return entropy
            transition was detected (a stronger injection signal than
            absolute entropy alone).
        distribution_type: Result of `_classify_distribution()`.
        size_category: Result of `_categorize_size()`.

    Returns:
        Confidence in [0.0, 1.0]. Every signal aligning (transition
        detected, encryption-like distribution, payload-sized region)
        pushes toward 1.0; a weak signal with no corroboration, or
        actively contrary signals (compression-like/structured
        distribution, mismatched size), pulls it back down.

    Raises:
        None.
    """
    confidence = base
    if transition_anomaly:
        confidence += config.CONFIDENCE_TRANSITION_BOOST
    if distribution_type == "encryption-like":
        confidence += config.CONFIDENCE_ENCRYPTION_LIKE_BOOST
    else:
        confidence -= config.CONFIDENCE_COMPRESSION_LIKE_PENALTY
    if size_category == "payload-sized":
        confidence += config.CONFIDENCE_PAYLOAD_SIZE_BOOST
    elif size_category == "small":
        confidence -= config.CONFIDENCE_SMALL_SIZE_PENALTY
    else:  # "large"
        confidence -= config.CONFIDENCE_LARGE_SIZE_PENALTY
    return max(0.0, min(1.0, confidence))


def _severity_for_confidence(confidence: float) -> str:
    """Map a confidence score to a severity band.

    Args:
        confidence: Confidence in [0.0, 1.0].

    Returns:
        "critical" >= `config.CONFIDENCE_CRITICAL`, "high" >=
        `config.CONFIDENCE_HIGH`, "medium" >= `config.CONFIDENCE_MEDIUM`,
        else "low" (still reported, but clearly low-confidence).

    Raises:
        None.
    """
    if confidence >= config.CONFIDENCE_CRITICAL:
        return "critical"
    if confidence >= config.CONFIDENCE_HIGH:
        return "high"
    if confidence >= config.CONFIDENCE_MEDIUM:
        return "medium"
    return "low"


def _merge_local_anomaly_regions(
    contrast_results: List[entropy.LocalContrastResult],
    transition_flags: List[bool],
) -> List[_CandidateRegion]:
    """Merge consecutive local-anomaly samples into contiguous candidate regions.

    Mirrors `entropy.merge_regions()`'s adjacency rule (samples merge into
    the same region only when contiguous in the sliding-window sequence),
    but keys on `is_anomaly` (from local contrast) rather than a global
    severity threshold.

    Args:
        contrast_results: Per-sample local contrast results, as produced
            by `entropy.compute_local_contrast()`.
        transition_flags: Per-sample transition-anomaly flags, as
            produced by `entropy.detect_entropy_transitions()`, aligned
            index-for-index with `contrast_results`.

    Returns:
        List of `_CandidateRegion`, one per merged contiguous local
        anomaly. A region's `peak_entropy`/`neighborhood_median`/
        `neighborhood_iqr` come from whichever sample in it has the
        highest entropy; `transition_anomaly` is True if any sample in
        it was flagged.

    Raises:
        None.
    """
    regions: List[_CandidateRegion] = []
    window_size = config.ENTROPY_WINDOW_SIZE
    step_size = config.ENTROPY_STEP_SIZE

    current_indices: List[int] = []
    previous_offset: Optional[int] = None

    def flush() -> None:
        if not current_indices:
            return
        peak_index = max(current_indices, key=lambda idx: contrast_results[idx].entropy)
        peak = contrast_results[peak_index]
        start_offset = contrast_results[current_indices[0]].offset
        end_offset = contrast_results[current_indices[-1]].offset + window_size
        regions.append(
            _CandidateRegion(
                start_offset=start_offset,
                end_offset=end_offset,
                peak_entropy=peak.entropy,
                neighborhood_median=peak.neighborhood_median,
                neighborhood_iqr=peak.neighborhood_iqr,
                transition_anomaly=any(transition_flags[i] for i in current_indices),
            )
        )

    for index, result in enumerate(contrast_results):
        is_contiguous = (
            previous_offset is not None and result.offset - previous_offset <= step_size
        )
        if result.is_anomaly and current_indices and is_contiguous:
            current_indices.append(index)
        elif result.is_anomaly:
            flush()
            current_indices = [index]
        else:
            flush()
            current_indices = []
        previous_offset = result.offset

    flush()
    return regions


def _build_candidate_finding(
    region: _CandidateRegion,
    data: bytes,
    module_name: str,
    source: str,
    file_path: Optional[str],
    extracted_relative_location: Optional[str],
    overlap: Optional[_RegionExtent],
) -> Finding:
    """Score one local-anomaly candidate region and build its Finding.

    Args:
        region: The merged candidate region.
        data: Full contents of the file the region was found in (used to
            slice out the region's bytes for the chi-square test).
        module_name: Module name to stamp on the returned finding.
        source: "raw_binary" or "extracted".
        file_path: Full path to the extracted file, or None for the raw
            firmware binary.
        extracted_relative_location: The file's location relative to the
            extraction root, or None for the raw firmware binary.
        overlap: The Binwalk-recognized format region this candidate
            overlaps, if any (it is only ever a candidate here, rather
            than dropped, because its entropy fell outside that format's
            expected range -- a format anomaly), or None if no format
            explanation exists at all.

    Returns:
        A scored Finding with `candidate=True` and the full confidence
        signal breakdown in its raw dict.

    Raises:
        None.
    """
    region_bytes = data[region.start_offset : region.end_offset]
    chi_square = entropy.chi_square_uniformity(region_bytes)
    distribution_type = _classify_distribution(chi_square)
    size_bytes = region.end_offset - region.start_offset
    size_category = _categorize_size(size_bytes)

    confidence = _compute_confidence(
        config.CONFIDENCE_LOCAL_ANOMALY_BASE,
        region.transition_anomaly,
        distribution_type,
        size_category,
    )
    severity = _severity_for_confidence(confidence)
    location_phrase = _location_phrase(source, region.start_offset, extracted_relative_location)

    if overlap is not None:
        _, _, _, description_text, expected_min, expected_max = overlap
        recognized_format = description_text
        expected_entropy_min, expected_entropy_max = expected_min, expected_max
        context = (
            f"claims to be {description_text} but entropy {region.peak_entropy:.3f} is outside "
            f"its expected range {expected_min:.1f}–{expected_max:.1f} — format anomaly"
        )
    else:
        recognized_format = None
        expected_entropy_min = expected_entropy_max = None
        context = "no recognized format explains this region"

    description = (
        f"Entropy anomaly {location_phrase} (peak {region.peak_entropy:.3f} bits/byte vs. "
        f"neighborhood median {region.neighborhood_median:.3f}) — {context}; "
        f"confidence {confidence:.2f} ({distribution_type}, {size_category})"
    )

    return Finding(
        module_name=module_name,
        severity=severity,
        offset=region.start_offset,
        description=description,
        evidence=f"confidence={confidence:.2f} peak_entropy={region.peak_entropy:.3f}",
        score=config.SEVERITY_SCORE_WEIGHTS[severity],
        raw={
            "start_offset": region.start_offset,
            "end_offset": region.end_offset,
            "peak_entropy": region.peak_entropy,
            "candidate": True,
            "confidence": confidence,
            "local_anomaly": True,
            "neighborhood_median": region.neighborhood_median,
            "neighborhood_iqr": region.neighborhood_iqr,
            "transition_anomaly": region.transition_anomaly,
            "chi_square": chi_square,
            "distribution_type": distribution_type,
            "region_size_bytes": size_bytes,
            "size_category": size_category,
            "recognized_format": recognized_format,
            "expected_entropy_min": expected_entropy_min,
            "expected_entropy_max": expected_entropy_max,
            "source": source,
            "file_path": file_path,
        },
    )


def _check_whole_file_anomaly(
    samples: List[entropy.EntropySample],
    data: bytes,
    known_regions: List[BinwalkRegion],
    module_name: str,
    source: str,
    file_path: Optional[str],
    extracted_relative_location: Optional[str],
) -> Optional[Finding]:
    """Flag a file as a whole-file candidate if it is uniformly high-entropy with no format explanation.

    Independent of local contrast: catches the case a local-anomaly scan
    misses entirely, a file with no internal contrast because it is
    encrypted throughout (its own neighborhood is just as high-entropy
    as it is, so nothing stands out locally).

    Args:
        samples: Ordered entropy samples covering the whole file.
        data: Full contents of the file.
        known_regions: Regions Binwalk recognized in this file. Any
            non-empty result is treated as "this file has a format
            explanation" and skips the check entirely.
        module_name: Module name to stamp on the returned finding.
        source: "raw_binary" or "extracted".
        file_path: Full path to the extracted file, or None for the raw
            firmware binary.
        extracted_relative_location: The file's location relative to the
            extraction root, or None for the raw firmware binary.

    Returns:
        A scored Finding if the file's overall median entropy exceeds
        `config.ENTROPY_GLOBAL_SUSPICIOUS_MEDIAN` and Binwalk recognized
        nothing in it at all; None otherwise.

    Raises:
        None.
    """
    if known_regions:
        return None

    entropies = [sample.entropy for sample in samples]
    overall_median = statistics.median(entropies)
    if overall_median <= config.ENTROPY_GLOBAL_SUSPICIOUS_MEDIAN:
        return None

    chi_square = entropy.chi_square_uniformity(data)
    distribution_type = _classify_distribution(chi_square)
    size_bytes = len(data)
    size_category = _categorize_size(size_bytes)
    transition_anomaly = any(entropy.detect_entropy_transitions(samples))

    confidence = _compute_confidence(
        config.CONFIDENCE_WHOLE_FILE_BASE, transition_anomaly, distribution_type, size_category
    )
    severity = _severity_for_confidence(confidence)
    location_phrase = _location_phrase(source, 0, extracted_relative_location)

    description = (
        f"Uniformly high-entropy file with no format explanation {location_phrase} "
        f"(overall median entropy {overall_median:.3f} bits/byte) — possible fully-encrypted "
        f"payload; confidence {confidence:.2f} ({distribution_type}, {size_category})"
    )

    return Finding(
        module_name=module_name,
        severity=severity,
        offset=0,
        description=description,
        evidence=f"confidence={confidence:.2f} overall_median_entropy={overall_median:.3f}",
        score=config.SEVERITY_SCORE_WEIGHTS[severity],
        raw={
            "start_offset": 0,
            "end_offset": size_bytes,
            "peak_entropy": max(entropies),
            "candidate": True,
            "confidence": confidence,
            "local_anomaly": False,
            "neighborhood_median": overall_median,
            "neighborhood_iqr": 0.0,
            "transition_anomaly": transition_anomaly,
            "chi_square": chi_square,
            "distribution_type": distribution_type,
            "region_size_bytes": size_bytes,
            "size_category": size_category,
            "recognized_format": None,
            "expected_entropy_min": None,
            "expected_entropy_max": None,
            "source": source,
            "file_path": file_path,
            "whole_file_anomaly": True,
        },
    )


def _analyze_file_entropy(
    samples: List[entropy.EntropySample],
    data: bytes,
    known_regions: List[BinwalkRegion],
    module_name: str,
    source: str,
    file_path: Optional[str],
    extracted_relative_location: Optional[str],
) -> Tuple[List[Finding], EntropySummary]:
    """Run the full context-aware entropy analysis for one file.

    Applies steps 3-6 of the module-level detection philosophy: local
    contrast, format-consistency drop, the independent whole-file check,
    and confidence scoring.

    Args:
        samples: Ordered entropy samples covering the whole file (already
            computed by the caller, which typically needs them for other
            purposes too -- e.g. the combined plot's curve).
        data: Full contents of the file.
        known_regions: Regions Binwalk recognized in this file.
        module_name: Module name to stamp on returned findings.
        source: "raw_binary" or "extracted".
        file_path: Full path to the extracted file, or None for the raw
            firmware binary.
        extracted_relative_location: The file's location relative to the
            extraction root, or None for the raw firmware binary.

    Returns:
        A (findings, summary) tuple.

    Raises:
        None.
    """
    summary = EntropySummary()
    if not samples:
        return [], summary

    region_extents = _recognized_format_extents(known_regions)
    contrast_results = entropy.compute_local_contrast(samples)
    transition_flags = entropy.detect_entropy_transitions(samples)
    candidate_regions = _merge_local_anomaly_regions(contrast_results, transition_flags)
    summary.regions_analyzed = len(candidate_regions)

    findings: List[Finding] = []
    for region in candidate_regions:
        overlap = _find_overlap(region.start_offset, region.end_offset, region_extents)
        if overlap is not None:
            _, _, _, _, expected_min, expected_max = overlap
            if expected_min <= region.peak_entropy <= expected_max:
                # Change 1: dropped, not a Finding -- and not downgraded
                # to a low/info severity either. It simply never existed.
                summary.dropped_format_consistent += 1
                continue

        summary.local_anomaly_candidates += 1
        findings.append(
            _build_candidate_finding(
                region, data, module_name, source, file_path, extracted_relative_location, overlap
            )
        )

    whole_file_finding = _check_whole_file_anomaly(
        samples, data, known_regions, module_name, source, file_path, extracted_relative_location
    )
    if whole_file_finding is not None:
        findings.append(whole_file_finding)
        summary.whole_file_anomalies += 1

    return findings, summary


def _process_raw_binary(
    path: Path, data: bytes
) -> Tuple[List[Finding], EntropySummary, List[entropy.EntropySample], BinwalkResult]:
    """Run the full pipeline flow on the raw firmware binary.

    Args:
        path: Path to the firmware binary.
        data: Full contents of the firmware binary.

    Returns:
        A (findings, summary, samples, binwalk_result) tuple. `samples`
        is returned for reuse by the caller (the combined plot's curve);
        `binwalk_result` has `known_regions=[]`/`extracted_dir=None` if
        Binwalk was unavailable or failed -- extraction is best-effort,
        never a hard dependency for getting a scan result.

    Raises:
        None.
    """
    samples = entropy.compute_entropy_samples(data)

    try:
        binwalk_result = binwalk_wrapper.extract(str(path), config.BINWALK_EXTRACTION_DIR)
    except AnalysisError as exc:
        logger.warning(
            "Binwalk extraction unavailable/failed for %s; continuing with raw "
            "entropy findings only: %s",
            path,
            exc,
        )
        binwalk_result = BinwalkResult(known_regions=[], extracted_dir=None)

    findings, summary = _analyze_file_entropy(
        samples, data, binwalk_result.known_regions, MODULE_NAME, "raw_binary", None, None
    )
    return findings, summary, samples, binwalk_result


def _analyze_extracted_file(
    filepath: Path, extraction_root: Path
) -> Tuple[List[Finding], EntropySummary]:
    """Run the full pipeline flow on one file Binwalk extracted.

    Args:
        filepath: Path to the extracted file.
        extraction_root: Root directory the file was extracted under.

    Returns:
        A (findings, summary) tuple. Both empty/zeroed if the file is
        empty.

    Raises:
        AnalysisError: If Binwalk is unavailable/fails while scanning
            this file, or the file cannot be read.
    """
    try:
        data = filepath.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read extracted file {filepath}: {exc}") from exc

    if not data:
        return [], EntropySummary()

    known_regions = binwalk_wrapper.scan_file(filepath)  # Step 1
    samples = entropy.compute_entropy_samples(data)  # Step 2 -- always runs
    relative_location = _relative_location(filepath, extraction_root)

    return _analyze_file_entropy(
        samples,
        data,
        known_regions,
        EXTRACTED_MODULE_NAME,
        "extracted",
        str(filepath),
        relative_location,
    )


def _depth_below_root(filepath: Path, root: Path) -> int:
    """Count how many directory levels `filepath` sits below `root`.

    Args:
        filepath: Path to a file somewhere under `root`.
        root: Extraction root directory.

    Returns:
        Number of path components between `root` and `filepath`
        (1 for a direct child file). Returns 0 if `filepath` is not
        actually under `root`.

    Raises:
        None.
    """
    try:
        return len(filepath.relative_to(root).parts)
    except ValueError:
        return 0


def _list_extracted_files(extracted_dir: Path) -> List[Path]:
    """List every file under `extracted_dir`, in a stable order.

    Args:
        extracted_dir: Root directory of Binwalk's extracted contents.

    Returns:
        Sorted list of file paths (directories excluded).

    Raises:
        None.
    """
    return sorted(entry for entry in extracted_dir.rglob("*") if entry.is_file())


def _select_extracted_files(
    extracted_dir: Path, entries: List[Path], raw_binary_size: int
) -> Dict[str, int]:
    """Filter extracted files by depth/size and assign each a sequential x-axis offset.

    A fast, purely local (no subprocess calls) pass: computing an
    extracted file's plot offset depends on the cumulative size of every
    file placed before it, so offsets must be assigned in a single
    sequential pass before the (potentially parallelized) analysis work
    in `_walk_extracted()` runs.

    Args:
        extracted_dir: Root directory of Binwalk's extracted contents.
        entries: Files to consider, as built by `_list_extracted_files()`.
        raw_binary_size: Size in bytes of the raw firmware binary --
            where the combined plot's x-axis for extracted files begins.

    Returns:
        Map of each selected file's string path to its assigned x-axis
        start offset -- `raw_binary_size` plus the sizes of every
        previously-selected extracted file, laid out sequentially. Files
        nested deeper than `config.EXTRACTED_MAX_DEPTH` or smaller than
        `config.EXTRACTED_MIN_FILE_SIZE` are excluded (logged at
        WARNING/skipped silently, respectively).

    Raises:
        None.
    """
    extracted_file_offsets: Dict[str, int] = {}
    cursor = raw_binary_size

    for entry in entries:
        depth = _depth_below_root(entry, extracted_dir)
        if depth > config.EXTRACTED_MAX_DEPTH:
            logger.warning(
                "Skipping %s: nested %d levels deep, exceeds EXTRACTED_MAX_DEPTH (%d)",
                entry,
                depth,
                config.EXTRACTED_MAX_DEPTH,
            )
            continue

        try:
            size = entry.stat().st_size
        except OSError:
            logger.warning("Could not stat extracted file %s; skipping", entry)
            continue
        if size < config.EXTRACTED_MIN_FILE_SIZE:
            continue

        extracted_file_offsets[str(entry)] = cursor
        cursor += size

    return extracted_file_offsets


def _walk_extracted(
    extracted_dir: Path, entries: List[Path], raw_binary_size: int
) -> Tuple[List[Finding], Dict[str, int], EntropySummary]:
    """Apply the full pipeline flow to every extracted file and lay them out on a combined x-axis.

    Binwalk's matryoshka mode already extracted every nested file's
    contents in one recursive pass during `binwalk_wrapper.extract()`, so
    a single walk of the final directory tree -- applying the pipeline
    flow to each file -- is equivalent to repeating it at every nesting
    level. A real extraction tree can contain thousands of files, each
    needing its own Binwalk subprocess call to cross-reference; those
    calls are dispatched across `config.EXTRACTED_SCAN_WORKERS` threads
    (each spends nearly all its time blocked on the subprocess, not
    holding Python's GIL, so threads give a real wall-clock speedup here)
    rather than run one at a time.

    Args:
        extracted_dir: Root directory of Binwalk's extracted contents.
        entries: Files to walk, as built by `_list_extracted_files()`.
        raw_binary_size: Size in bytes of the raw firmware binary --
            where the combined plot's x-axis for extracted files begins.

    Returns:
        A (findings, extracted_file_offsets, summary) tuple: combined
        findings and merged `EntropySummary` from analyzing every
        selected file (see `_select_extracted_files()` for the
        depth/size filtering -- a file that raises any exception during
        analysis is logged and skipped rather than aborting the whole
        walk), and the offset map `_select_extracted_files()` built.

    Raises:
        None.
    """
    extracted_file_offsets = _select_extracted_files(extracted_dir, entries, raw_binary_size)

    findings: List[Finding] = []
    summary = EntropySummary()
    with ThreadPoolExecutor(max_workers=config.EXTRACTED_SCAN_WORKERS) as executor:
        future_to_path = {
            executor.submit(_analyze_extracted_file, Path(path_str), extracted_dir): path_str
            for path_str in extracted_file_offsets
        }
        for future in as_completed(future_to_path):
            path_str = future_to_path[future]
            try:
                file_findings, file_summary = future.result()
                findings.extend(file_findings)
                summary.merge(file_summary)
            except Exception:
                # A single malformed/unreadable extracted file must never
                # abort analysis of the rest of the tree.
                logger.exception("Error analyzing extracted file %s; skipping", path_str)

    return findings, extracted_file_offsets, summary


def _cleanup_extracted_dir(extracted_dir: Optional[Path]) -> None:
    """Delete the extracted directory tree, logging the outcome. Never raises.

    Only ever removes `extracted_dir` itself (Binwalk's own extraction
    output) -- never the original firmware file, `output/`, or anything
    that existed before this run.

    Args:
        extracted_dir: Root directory of Binwalk's extracted contents, or
            None if nothing was ever extracted (a no-op in that case).

    Returns:
        None.

    Raises:
        None.
    """
    if extracted_dir is None:
        return
    try:
        if extracted_dir.is_dir():
            shutil.rmtree(extracted_dir)
            logger.info("Cleanup complete — removed %s", extracted_dir)
    except OSError as exc:
        logger.warning("Cleanup WARNING — could not remove %s: %s", extracted_dir, exc)


def _run_filesystem_checks(extracted_dir: Path) -> List[Finding]:
    """Run `modules/filesystem.py`'s checks against the extracted directory.

    Reuses the same extraction already on disk from `_process_raw_binary()`
    -- no second extraction. Filesystem checks are best-effort, like every
    other step in this pipeline: a failure here never aborts the run.

    Args:
        extracted_dir: Root directory of Binwalk's extracted contents.

    Returns:
        Findings from `filesystem.analyze()`, or an empty list if it
        raises.

    Raises:
        None.
    """
    try:
        return filesystem.analyze(str(extracted_dir))
    except (FileNotFoundError, AnalysisError) as exc:
        logger.warning("Filesystem analysis failed, continuing without it: %s", exc)
        return []


def _yara_finding_to_core(yara_finding: "yara_engine.Finding") -> Finding:
    """Adapt a modules/yara_engine.py Finding to core.Finding.

    yara_engine.py predates core.Finding and defines its own, differently
    shaped Finding dataclass (no `module_name`, `evidence`, or `raw`
    fields) -- see its module docstring. Everything YARA-specific (rule
    name, tags, matched strings, baseline-suppression state) is preserved
    in `raw`. Mirrors web/app.py's `_yara_finding_to_core()` (that one
    tags module_name="yara_engine" for the extracted-file/dashboard scan;
    this one tags "yara_engine_raw" for the raw-binary pass below).

    Args:
        yara_finding: A finding from `YaraEngine.scan_file()`.

    Returns:
        The equivalent `core.Finding`, tagged `module_name="yara_engine_raw"`.

    Raises:
        None.
    """
    severity = (
        yara_finding.severity if yara_finding.severity in config.SEVERITY_SCORE_WEIGHTS else "info"
    )
    return Finding(
        module_name=YARA_RAW_MODULE_NAME,
        severity=severity,
        offset=yara_finding.offset,
        description=yara_finding.description or f"YARA rule {yara_finding.rule!r} matched",
        evidence=yara_finding.rule,
        score=config.SEVERITY_SCORE_WEIGHTS.get(severity, 0),
        raw={
            "rule": yara_finding.rule,
            "namespace": yara_finding.namespace,
            "category": yara_finding.category,
            "file_path": yara_finding.file_path,
            "file_sha256": yara_finding.file_sha256,
            "tags": yara_finding.tags,
            "meta": yara_finding.meta,
            "matched_strings": [
                {"identifier": s.identifier, "offset": s.offset, "preview": s.preview}
                for s in yara_finding.strings
            ],
        },
    )


def _run_raw_yara_scan(path: Path) -> List[Finding]:
    """Run YARA against the raw firmware binary, unconditionally.

    Unlike the extracted-file YARA pass a caller might run separately,
    this always runs against `path` itself -- including firmware Binwalk
    can't extract anything from at all (e.g. ESP32 bare-metal images),
    where the extracted-file-only path would otherwise never see YARA
    run at all. Best-effort: a compile/scan failure is logged and treated
    as zero findings, never aborting the rest of the pipeline.

    Args:
        path: Path to the raw firmware binary.

    Returns:
        Findings adapted via `_yara_finding_to_core()`, module_name
        "yara_engine_raw". Empty list on failure or if every match is
        baseline-suppressed (moot here -- no baseline is loaded).

    Raises:
        None.
    """
    try:
        engine = yara_engine.YaraEngine(str(_YARA_RULES_DIR)).compile()
        raw_matches = engine.scan_file(path)
        return [
            _yara_finding_to_core(match) for match in raw_matches if not match.suppressed_by_baseline
        ]
    except Exception:
        logger.exception("Raw binary YARA scan failed, continuing without it")
        return []


def _run_raw_strings_scan(path: Path) -> List[Finding]:
    """Run modules/strings.py against the raw firmware binary, unconditionally.

    Same rationale as `_run_raw_yara_scan()`: this must run regardless of
    whether Binwalk extraction succeeded. `strings.analyze()` already
    returns proper `core.Finding` objects (module_name="strings"); each
    is retagged "strings_raw" here so raw-binary matches stay
    distinguishable from extracted-file string matches in the combined
    report.

    Args:
        path: Path to the raw firmware binary.

    Returns:
        Findings from `strings.analyze()`, retagged module_name
        "strings_raw". Empty list on failure.

    Raises:
        None.
    """
    try:
        raw_findings = strings.analyze(str(path))
    except Exception:
        logger.exception("Raw binary strings scan failed, continuing without it")
        return []
    for finding in raw_findings:
        finding.module_name = STRINGS_RAW_MODULE_NAME
    return raw_findings


def run_pipeline_with_summary(filepath: str) -> Tuple[List[Finding], EntropySummary]:
    """Run the full context-aware pipeline, returning findings and the entropy summary.

    Args:
        filepath: Absolute or relative path to the firmware binary.

    Returns:
        A (findings, summary) tuple. `findings` contains only anomaly
        candidates (format-consistent regions are dropped, never
        appearing here); `summary` carries the aggregate counts logged
        as "Entropy analysis summary:" (see the module docstring).

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: If the firmware file cannot be read.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read firmware file {filepath}: {exc}") from exc

    if not data:
        logger.warning("Firmware file %s is empty; skipping pipeline analysis", path)
        return [], EntropySummary()

    logger.info("Starting pipeline for %s (%d bytes)", path, len(data))

    extracted_dir: Optional[Path] = None
    all_findings: List[Finding] = []
    overall_summary = EntropySummary()

    try:
        primary_findings, raw_summary, samples, binwalk_result = _process_raw_binary(path, data)
        extracted_dir = binwalk_result.extracted_dir
        all_findings.extend(primary_findings)
        overall_summary.merge(raw_summary)

        logger.info(
            "Raw binary entropy: %d region(s) analyzed, %d dropped (format-consistent), "
            "%d local anomaly candidate(s), %d whole-file anomaly(ies)",
            raw_summary.regions_analyzed,
            raw_summary.dropped_format_consistent,
            raw_summary.local_anomaly_candidates,
            raw_summary.whole_file_anomalies,
        )

        # Unconditional -- runs regardless of whether Binwalk could
        # extract anything (extracted_dir may be None here, e.g. ESP32
        # bare-metal images Binwalk doesn't recognize at all). Without
        # this, firmware Binwalk can't extract never gets a YARA or
        # strings pass at all, since every other YARA/strings call in
        # this pipeline is scoped to the extracted tree below.
        raw_yara_findings = _run_raw_yara_scan(path)
        all_findings.extend(raw_yara_findings)
        logger.info("YARA raw binary scan: %d finding(s)", len(raw_yara_findings))

        raw_strings_findings = _run_raw_strings_scan(path)
        all_findings.extend(raw_strings_findings)
        logger.info("Strings raw binary scan: %d finding(s)", len(raw_strings_findings))

        extracted_findings: List[Finding] = []
        extracted_file_offsets: Dict[str, int] = {}
        if extracted_dir is not None:
            # Filesystem checks reuse this same extraction -- never a
            # second extraction -- and run regardless of
            # config.EXTRACTED_SCAN_ENABLED (that flag is specific to the
            # entropy-based extracted-file walk below).
            logger.info("Running filesystem checks on extracted contents...")
            filesystem_findings = _run_filesystem_checks(extracted_dir)
            fs_severity_counts = Counter(finding.severity for finding in filesystem_findings)
            logger.info(
                "Filesystem analysis: %d findings (%d high, %d medium, %d low)",
                len(filesystem_findings),
                fs_severity_counts.get("high", 0),
                fs_severity_counts.get("medium", 0),
                fs_severity_counts.get("low", 0),
            )
            all_findings.extend(filesystem_findings)

            if config.EXTRACTED_SCAN_ENABLED:
                entries = _list_extracted_files(extracted_dir)
                logger.info("Extracted %d files from %s, scanning...", len(entries), path)
                extracted_findings, extracted_file_offsets, ext_summary = _walk_extracted(
                    extracted_dir, entries, len(data)
                )
                overall_summary.merge(ext_summary)
                logger.info(
                    "Extracted file entropy: %d region(s) analyzed, %d dropped (format-consistent), "
                    "%d local anomaly candidate(s), %d whole-file anomaly(ies)",
                    ext_summary.regions_analyzed,
                    ext_summary.dropped_format_consistent,
                    ext_summary.local_anomaly_candidates,
                    ext_summary.whole_file_anomalies,
                )
                all_findings.extend(extracted_findings)

        # Plot before cleanup: extracted file paths must still exist on
        # disk to extend the entropy curve past the raw binary.
        try:
            entropy.generate_pipeline_plot(
                all_findings,
                path,
                extracted_file_offsets,
                config.DEFAULT_OUTPUT_DIR,
                raw_samples=samples,
                summary=overall_summary.as_dict(),
            )
        except AnalysisError:
            logger.exception("Pipeline entropy plot generation failed; continuing without plot")
    finally:
        _cleanup_extracted_dir(extracted_dir)

    severity_counts = Counter(finding.severity for finding in all_findings)
    logger.info(
        "Entropy analysis summary:\n"
        "  High-entropy regions analyzed: %d\n"
        "  Consistent with format (dropped): %d\n"
        "  Local anomaly candidates: %d\n"
        "  Whole-file anomalies: %d\n"
        "  Confidence breakdown: [critical: %d, high: %d, medium: %d, low: %d]",
        overall_summary.regions_analyzed,
        overall_summary.dropped_format_consistent,
        overall_summary.local_anomaly_candidates,
        overall_summary.whole_file_anomalies,
        severity_counts.get("critical", 0),
        severity_counts.get("high", 0),
        severity_counts.get("medium", 0),
        severity_counts.get("low", 0),
    )
    logger.info("Pipeline complete: %d finding(s)", len(all_findings))
    return all_findings, overall_summary


def run_pipeline(filepath: str) -> List[Finding]:
    """Run the full context-aware pipeline.

    Thin wrapper around `run_pipeline_with_summary()` that returns only
    the findings, preserving this function's original signature so
    `main.py` (and any other existing caller) needs no changes.

    Args:
        filepath: Absolute or relative path to the firmware binary.

    Returns:
        Candidate findings only -- see `run_pipeline_with_summary()`.

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: If the firmware file cannot be read.
    """
    findings, _summary = run_pipeline_with_summary(filepath)
    return findings


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Run the context-aware Binwalk extraction + entropy pipeline on a firmware image."
    )
    parser.add_argument("firmware", help="Path to firmware binary file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    cli_args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if cli_args.verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )

    try:
        pipeline_findings, pipeline_summary = run_pipeline_with_summary(cli_args.firmware)
    except FileNotFoundError as not_found_exc:
        logger.error("%s", not_found_exc)
        sys.exit(1)
    except AnalysisError as analysis_exc:
        logger.error("Pipeline failed: %s", analysis_exc)
        sys.exit(1)

    if not pipeline_findings:
        print("No suspicious indicators detected.")
    else:
        print(f"Detected {len(pipeline_findings)} finding(s):")
        for pipeline_finding in pipeline_findings:
            print(
                f"  [{pipeline_finding.severity.upper()}] ({pipeline_finding.module_name}) "
                f"score={pipeline_finding.score} - {pipeline_finding.description}"
            )
