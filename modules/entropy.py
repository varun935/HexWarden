"""Shannon entropy analysis module for HexWarden.

Computes byte-level Shannon entropy over a sliding window across a firmware
image to identify regions of high randomness that may indicate packed,
compressed, or encrypted payloads -- a common technique used to hide
firmware trojans from static signature scanning.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: One Finding per contiguous suspicious high-entropy
    region detected in the firmware image. As a side effect, a PNG plot
    of the entropy curve is written to the configured output directory.
"""

import argparse
import logging
import math
import sys
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
from numpy.lib.stride_tricks import sliding_window_view

import config
from core import AnalysisError, Finding

logger = logging.getLogger(__name__)

MODULE_NAME = "entropy"

# Severity rank used to compare severities when picking the peak of a
# merged region (higher rank = more severe).
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Colors used to highlight suspicious regions on the entropy plot, keyed
# by severity.
_REGION_PLOT_COLORS = {
    "low": "gold",
    "medium": "orange",
    "high": "orangered",
    "critical": "red",
}


@dataclass
class EntropySample:
    """One sliding-window entropy measurement.

    Public so other modules (e.g. `modules/firmware_pipeline.py`) can
    reuse the raw sample stream without recomputing entropy themselves.

    Attributes:
        offset: Byte offset in the file where the window begins.
        entropy: Shannon entropy of the window, in bits per byte.
    """

    offset: int
    entropy: float


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte sequence.

    Args:
        data: Raw bytes to compute entropy over.

    Returns:
        Entropy in bits per byte, ranging from 0.0 (perfectly uniform,
        e.g. all-zero bytes) to 8.0 (maximum randomness). Returns 0.0
        for empty input.

    Raises:
        None.
    """
    if not data:
        return 0.0

    length = len(data)
    byte_counts = Counter(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def compute_entropy_samples(data: bytes) -> List[EntropySample]:
    """Slide a window across firmware bytes and compute entropy at each step.

    Public entry point so other modules (e.g. the Binwalk extraction
    pipeline) can compute the entropy sample stream once and reuse it,
    rather than calling the higher-level `analyze()` and running entropy
    analysis twice.

    Args:
        data: Full contents of the firmware file.

    Returns:
        List of `EntropySample` values, one per window position, ordered
        by increasing offset. If the file is smaller than the configured
        window size, a single sample covering the whole file is returned
        (empty list only if `data` is empty).

    Raises:
        None.
    """
    samples: List[EntropySample] = []
    window_size = config.ENTROPY_WINDOW_SIZE
    step_size = config.ENTROPY_STEP_SIZE
    data_length = len(data)

    if data_length == 0:
        return samples

    if data_length < window_size:
        samples.append(EntropySample(offset=0, entropy=shannon_entropy(data)))
        return samples

    for offset in range(0, data_length - window_size + 1, step_size):
        window = data[offset : offset + window_size]
        samples.append(EntropySample(offset=offset, entropy=shannon_entropy(window)))

    return samples


def severity_for_entropy(entropy_value: float) -> Optional[str]:
    """Map an entropy value to a severity level using configured thresholds.

    Args:
        entropy_value: Shannon entropy value in bits per byte.

    Returns:
        Severity string ("low", "medium", "high", "critical"), or None
        if the entropy falls below the lowest threshold and should be
        treated as normal code/data.

    Raises:
        None.
    """
    if entropy_value >= config.ENTROPY_THRESHOLD_CRITICAL:
        return "critical"
    if entropy_value >= config.ENTROPY_THRESHOLD_HIGH:
        return "high"
    if entropy_value >= config.ENTROPY_THRESHOLD_MEDIUM:
        return "medium"
    if entropy_value >= config.ENTROPY_THRESHOLD_LOW:
        return "low"
    return None


def merge_regions(samples: List[EntropySample]) -> List[Finding]:
    """Merge consecutive suspicious windows into contiguous region findings.

    Public entry point so other modules can merge a sample stream they
    computed via `compute_entropy_samples()` without going through the
    file-reading `analyze()` wrapper.

    Args:
        samples: Ordered list of entropy samples covering the whole file.

    Returns:
        List of Finding objects, one per merged contiguous suspicious
        region. Two suspicious samples are merged into the same region
        only when they are adjacent in the sliding-window sequence (i.e.
        no normal-entropy gap between them); severity is derived from the
        peak entropy observed within the merged region.

    Raises:
        None.
    """
    findings: List[Finding] = []
    window_size = config.ENTROPY_WINDOW_SIZE
    step_size = config.ENTROPY_STEP_SIZE

    current_region: List[EntropySample] = []
    previous_offset: Optional[int] = None

    def flush_region() -> None:
        if not current_region:
            return
        peak_entropy = max(sample.entropy for sample in current_region)
        severity = severity_for_entropy(peak_entropy)
        if severity is None:
            return
        start_offset = current_region[0].offset
        end_offset = current_region[-1].offset + window_size
        findings.append(
            Finding(
                module_name=MODULE_NAME,
                severity=severity,
                offset=start_offset,
                description=(
                    f"High-entropy region spanning bytes {start_offset}-"
                    f"{end_offset} (peak entropy {peak_entropy:.3f} "
                    "bits/byte), consistent with compressed or encrypted "
                    "payload."
                ),
                evidence=f"peak_entropy={peak_entropy:.3f}",
                score=config.SEVERITY_SCORE_WEIGHTS[severity],
                raw={
                    "start_offset": start_offset,
                    "end_offset": end_offset,
                    "peak_entropy": peak_entropy,
                    "window_size": window_size,
                    "step_size": step_size,
                },
            )
        )

    for sample in samples:
        is_suspicious = severity_for_entropy(sample.entropy) is not None
        is_contiguous = (
            previous_offset is not None and sample.offset - previous_offset <= step_size
        )

        if is_suspicious and current_region and is_contiguous:
            current_region.append(sample)
        elif is_suspicious:
            flush_region()
            current_region = [sample]
        else:
            flush_region()
            current_region = []

        previous_offset = sample.offset

    flush_region()
    return findings


@dataclass
class LocalContrastResult:
    """One sample's entropy measured against its local neighborhood.

    Attributes:
        offset: Byte offset in the file where the sample's window begins.
        entropy: The sample's own Shannon entropy, in bits per byte.
        is_anomaly: True if the sample stands out from its neighborhood
            per `compute_local_contrast()`'s rule.
        neighborhood_median: Median entropy of the sample's neighborhood
            (robust to outliers, unlike the mean).
        neighborhood_iqr: Interquartile range of the neighborhood's
            entropy values -- a robust measure of local spread.
    """

    offset: int
    entropy: float
    is_anomaly: bool
    neighborhood_median: float
    neighborhood_iqr: float


def compute_local_contrast(samples: List[EntropySample]) -> List[LocalContrastResult]:
    """Measure each entropy sample against its local neighborhood.

    Implements HexWarden's context-aware detection: a sample is only
    anomalous if it stands out from the entropy *around* it, not merely
    because it exceeds a fixed global threshold -- a 7.9-entropy sample
    inside a 7.8-entropy compressed blob is unremarkable; the same value
    in the middle of 5.5-entropy code is a real outlier.

    Dead-space windows (entropy below `config.ENTROPY_DEADSPACE_THRESHOLD`
    -- zero-padding, unallocated sectors, filesystem gaps) are excluded
    from every neighborhood's median/IQR: a firmware image that is mostly
    empty space would otherwise drag a real region's neighborhood baseline
    toward 0.0 whenever padding falls on either side of it, making
    ordinary low-entropy content (e.g. plain code at ~4.9 bits/byte) look
    like a massive anomaly purely because of what's dead space nearby, not
    because of anything about the region itself.

    Excluding dead space is not enough on its own, though: a real,
    injected payload up to roughly `config.ENTROPY_NEIGHBORHOOD_BYTES`
    wide, isolated in a much larger sea of dead space (e.g. appended past
    a disk image's real content, with nothing but padding for megabytes
    behind it), would otherwise end up being the *only* real content
    within reach -- its own samples become its "neighborhood", comparing
    itself to itself, which can never register as an anomaly and never
    trips the too-little-neighborhood fallback either (there would be
    plenty of "real" samples -- they would just all be the payload). The
    immediate `config.ENTROPY_NEIGHBORHOOD_BYTES` around a sample is
    therefore treated as a guard band and excluded from its own
    statistics entirely; genuine training data for the median/IQR comes
    only from `config.ENTROPY_NEIGHBORHOOD_TRAINING_MULTIPLIER` times
    that radius further out still -- the same technique CFAR radar
    detectors use (guard cells around the cell under test, training cells
    beyond them) so a target never pollutes its own background estimate.
    If, after excluding dead space and the guard band, fewer than
    `config.ENTROPY_MIN_NEIGHBORHOOD_WINDOWS` real training samples
    remain, there is no meaningful neighborhood to contrast against at
    all, so that sample falls back to being judged on absolute entropy
    alone (via `severity_for_entropy()`) rather than local contrast.

    Reads `config.ENTROPY_NEIGHBORHOOD_BYTES`, `_ADAPTIVE_IQR_MULTIPLIER`,
    `_LOCAL_ANOMALY_MIN_DELTA`, `_LOCAL_CONTRAST_STRIDE`,
    `_DEADSPACE_THRESHOLD`, `_MIN_NEIGHBORHOOD_WINDOWS`, and
    `_NEIGHBORHOOD_TRAINING_MULTIPLIER` directly (rather than taking a
    `config` parameter) to match every other function in this module.

    For performance, the neighborhood's median and IQR are evaluated
    every `config.ENTROPY_LOCAL_CONTRAST_STRIDE` samples (a full-resolution
    evaluation is prohibitively slow on large firmware -- see the config
    comment) and linearly interpolated in between; the neighborhood is far
    wider than the sample step, so this costs negligible accuracy.

    Args:
        samples: Ordered entropy samples covering the whole file, as
            produced by `compute_entropy_samples()`.

    Returns:
        One `LocalContrastResult` per input sample, in the same order.
        Empty list if `samples` is empty.

    Raises:
        None.
    """
    if not samples:
        return []

    entropies = np.array([sample.entropy for sample in samples], dtype=np.float64)
    sample_count = len(entropies)

    # Dead-space entries are replaced with NaN so the nan-aware statistics
    # below skip them per-window automatically -- a region's neighborhood
    # baseline reflects only the real content around it, never the empty
    # gaps. The sample's own entropy (used for is_anomaly and reported in
    # the result) is untouched; this only changes what counts as *context*.
    real_mask = entropies >= config.ENTROPY_DEADSPACE_THRESHOLD
    entropies_for_neighborhood = np.where(real_mask, entropies, np.nan)

    step_size = config.ENTROPY_STEP_SIZE
    guard_radius_samples = max(1, config.ENTROPY_NEIGHBORHOOD_BYTES // step_size)
    radius_samples = guard_radius_samples * config.ENTROPY_NEIGHBORHOOD_TRAINING_MULTIPLIER
    window_size = radius_samples * 2 + 1

    if sample_count <= window_size:
        # Too few samples for a meaningful sliding neighborhood; treat the
        # whole stream (minus dead space) as every sample's neighborhood.
        # No guard band here -- there is nowhere else to look for training
        # data in a file this small, so the fallback below (triggered by
        # too few real samples) is what protects a small isolated blob.
        real_values = entropies[real_mask]
        real_count = len(real_values)
        if real_count > 0:
            median_value = float(np.median(real_values))
            q75, q25 = np.percentile(real_values, [75, 25])
            iqr_value = float(q75 - q25)
        else:
            median_value = 0.0
            iqr_value = 0.0
        medians = np.full(sample_count, median_value)
        iqrs = np.full(sample_count, iqr_value)
        real_counts = np.full(sample_count, real_count, dtype=np.float64)
    else:
        stride = max(1, config.ENTROPY_LOCAL_CONTRAST_STRIDE)

        # Deliberately unpadded: sliding_window_view over the raw array
        # yields one full, symmetric window per "interior" sample (from
        # radius_samples to sample_count - 1 - radius_samples). Padding
        # with a repeated/mirrored edge value would let a genuinely
        # anomalous region sitting near a file's start or end contaminate
        # its own neighborhood statistics -- e.g. a payload appended at
        # EOF, replicated outward by edge-padding, would drag the
        # neighborhood median up together with the anomaly itself and
        # mask the very anomaly this function exists to catch.
        #
        # The guard band itself is never materialized: rather than slide a
        # full 2*radius_samples+1-wide window and NaN out its middle (which
        # would double the per-window memory footprint for no benefit --
        # this loads a 184MB firmware image's worth of samples fine at the
        # old single-sided radius but not at 2x that), only the two
        # guard_radius_samples-wide training slices on either side of the
        # guard band are ever built.
        interior_count = sample_count - window_size + 1

        interior_eval_indices = np.arange(0, interior_count, stride)
        if interior_eval_indices[-1] != interior_count - 1:
            interior_eval_indices = np.append(interior_eval_indices, interior_count - 1)

        # A window-start index j corresponds to a center sample at
        # j + radius_samples. The left training slice for that center
        # starts at j (covering [center - radius_samples, center -
        # guard_radius_samples - 1]); the right slice starts at
        # j + radius_samples + guard_radius_samples + 1 (covering
        # [center + guard_radius_samples + 1, center + radius_samples]).
        # Both are guard_radius_samples wide and drawn from the same
        # guard_radius_samples-wide sliding view.
        annulus_windows = sliding_window_view(entropies_for_neighborhood, guard_radius_samples)
        left_starts = interior_eval_indices
        right_starts = interior_eval_indices + radius_samples + guard_radius_samples + 1

        # Fancy indexing (an array of indices, not a slice) always copies,
        # so these copies are independent of the underlying view and of
        # each other.
        eval_left = annulus_windows[left_starts]
        eval_right = annulus_windows[right_starts]
        eval_windows = np.concatenate([eval_left, eval_right], axis=1)
        del eval_left, eval_right

        real_count_eval = np.count_nonzero(~np.isnan(eval_windows), axis=1)

        # A window with no real training data beyond the guard band yields
        # an all-NaN slice; np.nanpercentile warns and returns NaN for
        # those rather than raising. The placeholder 0.0 substituted for
        # them is never actually used for detection since real_count_eval
        # already marks those points for the absolute-entropy fallback.
        # numpy's all-NaN-slice warning is emitted via Python's `warnings`
        # module (from numpy.lib.nanfunctions), not via numpy's
        # floating-point error-state mechanism -- np.errstate does not
        # silence it, so it is suppressed here explicitly instead.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=RuntimeWarning)
            q25_eval, median_eval, q75_eval = np.nanpercentile(
                eval_windows, [25, 50, 75], axis=1
            )
        median_eval = np.nan_to_num(median_eval, nan=0.0)
        iqr_eval = np.nan_to_num(q75_eval - q25_eval, nan=0.0)

        # Map window-local indices back to sample indices (a window
        # starting at array index i is centered on sample i + radius_samples).
        sample_eval_indices = interior_eval_indices + radius_samples

        # Samples within radius_samples of either edge have no full
        # symmetric window; np.interp clamps out-of-range x to the
        # nearest evaluated (interior) y-value rather than extrapolating.
        # That clamp is only filled in as a placeholder here -- it is
        # overwritten below for every edge sample with a real one-sided
        # computation, because clamping to the nearest interior center is
        # NOT safe in general: that nearest center's own training annulus
        # can itself reach past the edge and into a genuine anomaly
        # narrower than radius_samples sitting right at the file boundary
        # (e.g. a payload appended at EOF) -- which would silently
        # contaminate every edge sample's "borrowed" stats with the very
        # anomaly they need to be judged against.
        full_indices = np.arange(sample_count)
        medians = np.interp(full_indices, sample_eval_indices, median_eval)
        iqrs = np.interp(full_indices, sample_eval_indices, iqr_eval)
        real_counts = np.interp(
            full_indices, sample_eval_indices, real_count_eval.astype(np.float64)
        )

        # True edge samples get a genuine ONE-SIDED annulus instead: the
        # only side that exists at all is guard-banded and used directly.
        # Each edge zone is only radius_samples samples wide, so computing
        # it directly (no striding) costs nothing next to the interior
        # pass above. The two zones, plus the interior range handled by
        # interpolation above, exactly partition every sample -- there is
        # no gap and no overlap.
        def _apply_one_sided_edge(edge_indices: np.ndarray, starts: np.ndarray) -> None:
            valid = (starts >= 0) & (starts <= sample_count - guard_radius_samples)
            if not np.any(valid):
                return
            edge_indices = edge_indices[valid]
            edge_windows = annulus_windows[starts[valid]]
            edge_real_counts = np.count_nonzero(~np.isnan(edge_windows), axis=1)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=RuntimeWarning)
                q25_edge, median_edge, q75_edge = np.nanpercentile(
                    edge_windows, [25, 50, 75], axis=1
                )
            medians[edge_indices] = np.nan_to_num(median_edge, nan=0.0)
            iqrs[edge_indices] = np.nan_to_num(q75_edge - q25_edge, nan=0.0)
            real_counts[edge_indices] = edge_real_counts

        left_edge_indices = np.arange(0, min(radius_samples, sample_count))
        _apply_one_sided_edge(left_edge_indices, left_edge_indices + guard_radius_samples + 1)

        right_edge_indices = np.arange(max(0, sample_count - radius_samples), sample_count)
        _apply_one_sided_edge(right_edge_indices, right_edge_indices - radius_samples)

    multiplier = config.ENTROPY_ADAPTIVE_IQR_MULTIPLIER
    min_delta = config.ENTROPY_LOCAL_ANOMALY_MIN_DELTA
    min_real_windows = config.ENTROPY_MIN_NEIGHBORHOOD_WINDOWS

    results: List[LocalContrastResult] = []
    for index, sample in enumerate(samples):
        median_value = float(medians[index])
        iqr_value = float(iqrs[index])

        if real_counts[index] < min_real_windows:
            # Isolated blob surrounded (almost) entirely by dead space --
            # there is no real neighborhood left to contrast against.
            # Judge it on absolute entropy alone instead, using the same
            # thresholds merge_regions() uses, rather than comparing it to
            # a neighborhood baseline that is itself mostly padding.
            is_anomaly = severity_for_entropy(sample.entropy) in ("high", "critical")
        else:
            delta = sample.entropy - median_value
            is_anomaly = delta > (multiplier * iqr_value) and delta >= min_delta

        results.append(
            LocalContrastResult(
                offset=sample.offset,
                entropy=sample.entropy,
                is_anomaly=is_anomaly,
                neighborhood_median=median_value,
                neighborhood_iqr=iqr_value,
            )
        )
    return results


def detect_entropy_transitions(samples: List[EntropySample]) -> List[bool]:
    """Flag samples sitting inside a sharp entropy spike-and-return.

    The fingerprint of an injected payload is a sharp transition -- low
    entropy, then a sudden jump to high, then a sudden drop back down --
    as opposed to the gradual entropy drift typical of a natural
    code-to-data boundary. Reads `config.ENTROPY_TRANSITION_DELTA` and
    `config.ENTROPY_PAYLOAD_SIZE_MAX` directly, matching every other
    function in this module.

    Args:
        samples: Ordered entropy samples covering the whole file.

    Returns:
        One bool per input sample (True if it falls within a detected
        rising-edge-to-falling-edge span, inclusive), in the same order.
        All False if fewer than 3 samples are given.

    Raises:
        None.
    """
    sample_count = len(samples)
    if sample_count < 3:
        return [False] * sample_count

    entropies = np.array([sample.entropy for sample in samples], dtype=np.float64)
    diffs = np.diff(entropies)
    delta = config.ENTROPY_TRANSITION_DELTA

    rising = np.where(diffs >= delta)[0]
    falling = np.where(diffs <= -delta)[0]
    flags = np.zeros(sample_count, dtype=bool)
    if rising.size == 0 or falling.size == 0:
        return flags.tolist()

    step_size = config.ENTROPY_STEP_SIZE
    max_gap_samples = max(1, config.ENTROPY_PAYLOAD_SIZE_MAX // step_size)

    # For each rising edge, the nearest falling edge at or after it (if
    # any) within max_gap_samples closes a spike-and-return span.
    fall_positions = np.searchsorted(falling, rising, side="left")
    for rise_index, fall_position in zip(rising, fall_positions):
        if fall_position >= falling.size:
            continue
        fall_index = falling[fall_position]
        if rise_index < fall_index <= rise_index + max_gap_samples:
            flags[rise_index : fall_index + 2] = True

    return flags.tolist()


def chi_square_uniformity(data: bytes) -> float:
    """Compute the chi-square statistic of a byte sequence against a uniform distribution.

    Encrypted data is close to perfectly uniform across all 256 byte
    values; compressed data retains slight residual structure (from
    Huffman/entropy coding), giving it a measurably higher chi-square
    statistic. Used to modulate confidence, not as a hard filter -- see
    `modules/firmware_pipeline.py`.

    Args:
        data: Raw bytes of the region to test.

    Returns:
        The chi-square goodness-of-fit statistic (255 degrees of freedom)
        against a uniform distribution over the 256 byte values. Lower is
        more uniform. 0.0 for empty input.

    Raises:
        None.
    """
    if not data:
        return 0.0

    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    expected = len(data) / 256.0
    chi_square = np.sum(((counts - expected) ** 2) / expected)
    return float(chi_square)


def generate_plot(
    samples: List[EntropySample],
    findings: List[Finding],
    firmware_path: Path,
    output_dir: Path,
    extraction_boundary_offset: Optional[int] = None,
) -> Path:
    """Render and save an entropy-vs-offset plot with threshold lines.

    Public entry point so other modules (e.g. the Binwalk extraction
    pipeline) can render a combined plot from their own sample/finding
    lists without duplicating the plotting logic.

    Args:
        samples: Ordered entropy samples across the firmware file.
        findings: Detected suspicious regions to highlight on the plot.
        firmware_path: Path to the analyzed firmware file (used for
            naming the output plot).
        output_dir: Directory in which to save the PNG plot.
        extraction_boundary_offset: If provided, draws a vertical dashed
            marker line at this offset labeled "Extraction begins", used
            by the pipeline to indicate where raw-binary entropy analysis
            ends and walking Binwalk's extracted contents begins.

    Returns:
        Path to the saved PNG file.

    Raises:
        AnalysisError: If the plot cannot be rendered or saved.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)

        offsets = [sample.offset for sample in samples]
        entropies = [sample.entropy for sample in samples]

        figure, axis = plt.subplots(figsize=(12, 6))
        axis.plot(offsets, entropies, color="steelblue", linewidth=1.0, label="Entropy")

        threshold_lines = (
            (config.ENTROPY_THRESHOLD_LOW, "low"),
            (config.ENTROPY_THRESHOLD_MEDIUM, "medium"),
            (config.ENTROPY_THRESHOLD_HIGH, "high"),
            (config.ENTROPY_THRESHOLD_CRITICAL, "critical"),
        )
        for threshold_value, label in threshold_lines:
            axis.axhline(y=threshold_value, linestyle="--", linewidth=0.8, color="gray")
            axis.text(
                offsets[-1] if offsets else 0,
                threshold_value,
                f" {label}",
                va="center",
                fontsize=8,
                color="gray",
            )

        for finding in findings:
            if "start_offset" not in finding.raw or "end_offset" not in finding.raw:
                continue
            axis.axvspan(
                finding.raw["start_offset"],
                finding.raw["end_offset"],
                color=_REGION_PLOT_COLORS.get(finding.severity, "red"),
                alpha=0.3,
            )

        if extraction_boundary_offset is not None:
            axis.axvline(
                x=extraction_boundary_offset,
                linestyle=":",
                linewidth=1.5,
                color="black",
                label="Extraction begins",
            )

        axis.set_xlabel("File Offset (bytes)")
        axis.set_ylabel("Shannon Entropy (bits/byte)")
        axis.set_ylim(0, config.ENTROPY_MAX_VALUE)
        axis.set_title(f"Entropy Analysis: {firmware_path.name}")
        axis.legend(loc="lower right")
        figure.tight_layout()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_path = output_dir / f"entropy_{firmware_path.stem}_{timestamp}.png"
        figure.savefig(plot_path, dpi=150)
        plt.close(figure)

        logger.info("Saved entropy plot to %s", plot_path)
        return plot_path
    except OSError as exc:
        raise AnalysisError(f"Failed to save entropy plot: {exc}") from exc


def _truncate(text: str, max_chars: int) -> str:
    """Truncate a label string to at most `max_chars` characters.

    Args:
        text: Text to truncate.
        max_chars: Maximum length of the returned string.

    Returns:
        `text[:max_chars]`.

    Raises:
        None.
    """
    return text[:max_chars]


# Highlight colour per confidence-derived severity band -- every finding
# the context-aware pipeline produces is already a candidate (format-
# consistent regions are dropped before ever becoming a Finding), so
# colour is driven purely by confidence rather than a separate
# expected/anomaly/suspicious category.
_CONFIDENCE_PLOT_COLORS = {
    "critical": "red",
    "high": "orange",
    "medium": "#FFC107",  # amber
    "low": "gray",
}


def _pipeline_plot_style(finding: Finding) -> Tuple[Optional[str], Optional[float], Optional[str]]:
    """Determine one candidate finding's plot highlight colour/alpha/label.

    Args:
        finding: A candidate finding produced by the context-aware
            pipeline (raw dict carries `confidence`/`recognized_format`).

    Returns:
        A (color, alpha, label) tuple, keyed off `finding.severity`
        (itself derived from confidence -- see
        `modules/firmware_pipeline.py`): red/critical, orange/high,
        amber/medium all get a highlight and a label; gray/low gets a
        highlight but no label (too minor to clutter the plot with text).

    Raises:
        None.
    """
    color = _CONFIDENCE_PLOT_COLORS.get(finding.severity, "gray")
    confidence = finding.raw.get("confidence")
    confidence_str = f"{confidence:.2f}" if confidence is not None else "?"

    if finding.severity == "low":
        return color, 0.20, None

    recognized_format = finding.raw.get("recognized_format")
    if recognized_format:
        subject = _truncate(recognized_format, config.PLOT_FORMAT_LABEL_MAX_CHARS)
    else:
        subject = "Unexplained"
    return color, 0.35, f"{subject} ({confidence_str})"


def _finding_plot_span(
    finding: Finding, extracted_file_offsets: Dict[str, int]
) -> Optional[Tuple[int, int]]:
    """Compute a finding's (start, end) byte span on the pipeline plot's combined x-axis.

    Args:
        finding: A finding produced by the pipeline.
        extracted_file_offsets: Maps each extracted file's string path to
            its x-axis start offset (see `generate_pipeline_plot`).

    Returns:
        A (start, end) tuple in combined-plot x-axis coordinates: the
        finding's raw-dict offsets unchanged for a raw-binary finding,
        or shifted by its file's assigned base offset for an extracted
        finding. None if the finding has no offset info, or its file
        path is not in `extracted_file_offsets` (e.g. it was filtered
        out before an offset was assigned).

    Raises:
        None.
    """
    if "start_offset" not in finding.raw or "end_offset" not in finding.raw:
        return None

    start = finding.raw["start_offset"]
    end = finding.raw["end_offset"]

    if finding.raw.get("source") == "extracted":
        base_offset = extracted_file_offsets.get(finding.raw.get("file_path"))
        if base_offset is None:
            return None
        start += base_offset
        end += base_offset

    return start, end


def generate_pipeline_plot(
    all_findings: List[Finding],
    firmware_path: Path,
    extracted_file_offsets: Dict[str, int],
    output_dir: Path,
    raw_samples: Optional[List[EntropySample]] = None,
    summary: Optional[Dict[str, int]] = None,
) -> Path:
    """Render and save the pipeline's combined entropy plot.

    Unlike `generate_plot()` (used by standalone `analyze()`), this draws
    one continuous entropy curve spanning the raw firmware binary
    followed by every extracted file laid out sequentially on the same
    x-axis, colour-codes each finding's highlighted region by its
    confidence-derived severity, and marks each extracted file's boundary
    with a dotted line and filename label. Every finding passed in is
    already a candidate -- format-consistent regions are dropped before
    ever becoming a Finding (see `modules/firmware_pipeline.py`), so this
    plot shows only anomaly candidates, never the dropped-consistent
    regions. `generate_plot()` itself is untouched -- standalone entropy
    analysis still uses the simple, threshold-based plot.

    Args:
        all_findings: Every candidate finding from the pipeline run (both
            module_name="firmware_pipeline" and
            "firmware_pipeline_extracted").
        firmware_path: Path to the analyzed firmware file (used for
            naming the output plot and the title).
        extracted_file_offsets: Maps each extracted file's string path
            (matching `finding.raw["file_path"]`) to its x-axis start
            offset -- the raw binary's size plus the sizes of every
            previously-placed extracted file. Extracted files must still
            exist on disk when this is called (the pipeline calls this
            before cleanup); their bytes are read here to extend the
            entropy curve past the raw binary.
        output_dir: Directory in which to save the PNG plot.
        raw_samples: The raw firmware's already-computed entropy sample
            stream, if the caller has one (avoids re-reading and
            re-analyzing a potentially large firmware file a second
            time). Computed from `firmware_path` if not provided.
        summary: Optional dict with `regions_analyzed`,
            `dropped_format_consistent`, `local_anomaly_candidates`, and
            `whole_file_anomalies` counts (see
            `modules/firmware_pipeline.py`'s `EntropySummary`), shown in
            the title alongside the severity counts. Omitted from the
            title if not provided.

    Returns:
        Path to the saved PNG file.

    Raises:
        AnalysisError: If the firmware file cannot be read, or the plot
            cannot be rendered or saved.
    """
    try:
        if raw_samples is None:
            raw_samples = compute_entropy_samples(firmware_path.read_bytes())

        output_dir.mkdir(parents=True, exist_ok=True)

        figure, axis = plt.subplots(figsize=(14, 6))

        offsets = [sample.offset for sample in raw_samples]
        entropies = [sample.entropy for sample in raw_samples]
        axis.plot(offsets, entropies, color="steelblue", linewidth=1.0)
        plot_x_max = offsets[-1] if offsets else 0

        # Rough upper-bound estimate of the plot's total x-axis span, known
        # before drawing since every extracted file's offset is already
        # assigned; used only to thin boundary labels (see below), not for
        # anything analysis-affecting.
        estimated_span = max([plot_x_max] + list(extracted_file_offsets.values()))
        min_label_spacing = estimated_span * config.PLOT_MIN_BOUNDARY_LABEL_SPACING_FRACTION
        last_labeled_offset: Optional[int] = None

        for file_path_str, base_offset in sorted(
            extracted_file_offsets.items(), key=lambda item: item[1]
        ):
            file_path = Path(file_path_str)
            try:
                file_samples = compute_entropy_samples(file_path.read_bytes())
            except OSError:
                logger.warning(
                    "Could not read %s for pipeline plot; skipping its entropy curve", file_path
                )
                file_samples = []

            if file_samples:
                file_offsets = [base_offset + sample.offset for sample in file_samples]
                file_entropies = [sample.entropy for sample in file_samples]
                axis.plot(file_offsets, file_entropies, color="steelblue", linewidth=1.0)
                plot_x_max = max(plot_x_max, file_offsets[-1])

            # Every file's curve and finding highlights are drawn regardless
            # (above/below), but the boundary marker + label are thinned out
            # where files sit too close together to stay legible.
            if last_labeled_offset is None or (base_offset - last_labeled_offset) >= min_label_spacing:
                axis.axvline(x=base_offset, linestyle=":", linewidth=1.2, color="black")
                axis.text(
                    base_offset,
                    config.ENTROPY_MAX_VALUE * 0.99,
                    _truncate(file_path.name, config.PLOT_FILENAME_LABEL_MAX_CHARS),
                    rotation=90,
                    va="top",
                    ha="right",
                    fontsize=6,
                    color="black",
                )
                last_labeled_offset = base_offset

        threshold_lines = (
            (config.ENTROPY_THRESHOLD_LOW, "low"),
            (config.ENTROPY_THRESHOLD_MEDIUM, "medium"),
            (config.ENTROPY_THRESHOLD_HIGH, "high"),
            (config.ENTROPY_THRESHOLD_CRITICAL, "critical"),
        )
        for threshold_value, label in threshold_lines:
            axis.axhline(y=threshold_value, linestyle="--", linewidth=0.8, color="gray")
            axis.text(
                plot_x_max, threshold_value, f" {label}", va="center", fontsize=8, color="gray"
            )

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        highlight_spans: List[Tuple[int, int, str, float, Optional[str]]] = []

        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

            color, alpha, label = _pipeline_plot_style(finding)
            if color is None:
                continue
            span = _finding_plot_span(finding, extracted_file_offsets)
            if span is None:
                continue
            highlight_spans.append((span[0], span[1], color, alpha, label))

        # Every finding's highlighted region is still drawn (a dense cluster
        # of overlapping highlights is a legitimate "lots of activity here"
        # signal), but region labels are thinned like boundary labels above
        # -- text stacked on itself is unreadable either way.
        highlight_spans.sort(key=lambda item: item[0])
        last_label_offset = None
        for start, end, color, alpha, label in highlight_spans:
            axis.axvspan(start, end, color=color, alpha=alpha)
            if label is not None and (
                last_label_offset is None or (start - last_label_offset) >= min_label_spacing
            ):
                axis.text(
                    (start + end) / 2,
                    config.ENTROPY_MAX_VALUE * 0.9,
                    label,
                    ha="center",
                    fontsize=7,
                    color="black",
                )
                last_label_offset = start

        axis.set_xlabel("Byte Offset (raw binary, then extracted files sequentially)")
        axis.set_ylabel("Shannon Entropy (bits/byte)")
        axis.set_ylim(0, config.ENTROPY_MAX_VALUE)

        title = f"HexWarden — {firmware_path.name}\n"
        if summary is not None:
            title += (
                f"Analyzed: {summary.get('regions_analyzed', 0)} | "
                f"Dropped: {summary.get('dropped_format_consistent', 0)} | "
                f"Local candidates: {summary.get('local_anomaly_candidates', 0)} | "
                f"Whole-file: {summary.get('whole_file_anomalies', 0)}\n"
            )
        title += (
            f"Critical: {severity_counts['critical']} | High: {severity_counts['high']} | "
            f"Medium: {severity_counts['medium']} | Low: {severity_counts['low']}"
        )
        axis.set_title(title)

        axis.legend(
            handles=[
                Line2D([0], [0], color="steelblue", linewidth=1.5, label="Entropy (blue line)"),
                Patch(facecolor="red", alpha=0.35, label="Critical confidence (red)"),
                Patch(facecolor="orange", alpha=0.35, label="High confidence (orange)"),
                Patch(facecolor="#FFC107", alpha=0.35, label="Medium confidence (amber)"),
                Patch(facecolor="gray", alpha=0.20, label="Low confidence (grey)"),
                Line2D(
                    [0], [0], color="black", linestyle=":", linewidth=1.2,
                    label="Extraction boundary (dotted line)",
                ),
            ],
            loc="upper right",
            fontsize=7,
        )
        figure.tight_layout()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        plot_path = output_dir / f"entropy_{firmware_path.stem}_{timestamp}.png"
        figure.savefig(plot_path, dpi=150)
        plt.close(figure)

        logger.info("Saved pipeline entropy plot to %s", plot_path)
        return plot_path
    except OSError as exc:
        raise AnalysisError(f"Failed to generate pipeline entropy plot: {exc}") from exc


def analyze(filepath: str) -> List[Finding]:
    """Analyze a firmware file for high-entropy regions.

    High-entropy regions are indicative of packed, compressed, or
    encrypted payloads, which is a common technique used to hide
    firmware trojans from static signature scanning.

    Args:
        filepath: Absolute or relative path to the firmware binary.

    Returns:
        List of Finding objects, one per detected suspicious high-entropy
        region. Empty list if no suspicious regions are found.

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: If the file cannot be read or plot generation fails.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read firmware file {filepath}: {exc}") from exc

    logger.info("Computing entropy for %s (%d bytes)", path, len(data))

    if not data:
        logger.warning("Firmware file %s is empty; skipping entropy analysis", path)
        return []

    samples = compute_entropy_samples(data)
    findings = merge_regions(samples)

    try:
        generate_plot(samples, findings, path, config.DEFAULT_OUTPUT_DIR)
    except AnalysisError:
        logger.exception("Entropy plot generation failed; continuing without plot")

    logger.info("Entropy analysis complete: %d suspicious region(s) found", len(findings))
    return findings


def _main() -> None:
    """Command-line entry point for standalone module execution.

    Allows `python -m modules.entropy firmware.bin` to run entropy
    analysis and print a human-readable summary. This is the only place
    in this module that writes to stdout -- the `analyze()` function
    itself never prints, so importing this module has no side effects.

    Args:
        None. Arguments are read from sys.argv via argparse.

    Returns:
        None.

    Raises:
        SystemExit: If the firmware file argument is missing/invalid, or
            if analysis fails.
    """
    parser = argparse.ArgumentParser(
        description="Run Shannon entropy analysis on a firmware image."
    )
    parser.add_argument("firmware", help="Path to firmware binary file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )

    try:
        findings = analyze(args.firmware)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except AnalysisError as exc:
        logger.error("Analysis failed: %s", exc)
        sys.exit(1)

    if not findings:
        print("No suspicious entropy regions detected.")
        return

    print(f"Detected {len(findings)} suspicious entropy region(s):")
    for finding in findings:
        print(
            f"  [{finding.severity.upper()}] offset={finding.offset} "
            f"score={finding.score} - {finding.description}"
        )


if __name__ == "__main__":
    _main()
