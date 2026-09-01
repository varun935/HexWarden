"""Golden-image comparison (Mode A) for HexWarden.

Compares a suspect firmware against a known-clean golden reference and
identifies what exists in the suspect that does NOT exist in the golden
image. Legitimate content -- compression, binary blobs, crypto keys, ELF
sections -- exists in both firmwares and cancels out in the diff, leaving
only genuinely injected or modified content. This produces near-zero
false positives when a reference is available, unlike the heuristic
entropy pipeline (`modules/firmware_pipeline.py`), which has no ground
truth to compare against.

Four layers, each narrowing down to genuine differences:

    1. Content-defined chunking: both images are split into variable-size
       chunks at rolling-hash-determined boundaries (the rsync/rolling-
       hash technique), not fixed offsets. An insertion only shifts the
       chunks immediately around it -- everything downstream re-aligns
       naturally, so a single injected payload never makes the rest of
       the firmware falsely appear changed.
    2. Hash-based block diff: every chunk's SHA-256 is compared against
       the set of all golden chunk hashes. A suspect chunk whose hash
       exists in golden is definitionally unchanged (it exists verbatim
       in the clean firmware) and is dropped instantly -- this is what
       eliminates the vast majority of a lightly-modified image before
       any deeper analysis runs.
    3. Entropy comparison: each surviving (changed/new) chunk's Shannon
       entropy is compared against its approximate golden counterpart (by
       position -- chunks that survive Layer 2 are, by construction, ones
       whose content isn't found anywhere in golden, so position-based
       comparison here is safe). A low-entropy golden region replaced by
       high-entropy suspect content is the strongest signal this module
       produces: a plausible payload injection.
    4. Structural diff via Binwalk: golden and suspect are both scanned,
       and any recognized structure present in suspect with no positional
       counterpart in golden is flagged too -- catching injected content
       even when the attacker was careful about entropy (e.g. injecting
       another compressed blob rather than raw encrypted bytes).

Inputs:
    golden_path (str): Path to a known-clean reference firmware image.
    suspect_path (str): Path to the firmware image being analyzed.

Outputs:
    List[Finding]: One Finding per changed/new/grown region identified in
    the suspect firmware relative to the golden reference. Empty list if
    the two images are identical (by content, not necessarily by byte
    layout).
"""

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config
from core import AnalysisError, Finding
from modules import binwalk_wrapper
from modules.binwalk_wrapper import BinwalkRegion
from modules.entropy import shannon_entropy

logger = logging.getLogger(__name__)

MODULE_NAME = "golden_diff"

# Polynomial rolling hash constants (Layer 1). Not cryptographic -- only
# needs reasonable avalanche behavior to place chunk boundaries, unlike
# the SHA-256 used for the actual content comparison in Layer 2.
_HASH_BASE = 257
_HASH_MOD = 1 << 32

# Firmware images routinely contain long runs of a single repeated byte
# (zero-padded flash regions, erased sectors); feeding a raw byte value
# straight into a multiplicative rolling hash means a run of 0x00 bytes
# drives the hash to a fixed point (0 * BASE + 0 = 0 forever) and never
# produces a natural boundary, collapsing every such run into pathological
# minimum-size chunks. Each byte is instead mapped through this table of
# deterministic pseudo-random 32-bit values before entering the hash --
# the standard "gear table" fix used by real content-defined-chunking
# algorithms (e.g. FastCDC) for exactly this failure mode. Deterministic
# (seeded from each byte value, not truly random) so chunking results are
# reproducible across runs.
_GEAR_TABLE: List[int] = [
    int.from_bytes(hashlib.sha256(bytes([_byte])).digest()[:4], "big") for _byte in range(256)
]


@dataclass
class _Chunk:
    """One content-defined chunk of a firmware image.

    Attributes:
        start: Byte offset where the chunk begins.
        end: Byte offset where the chunk ends (exclusive).
        sha256: Hex digest of the chunk's contents.
    """

    start: int
    end: int
    sha256: str


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


def _rolling_hash_boundaries(data: bytes) -> List[int]:
    """Find content-defined chunk boundary offsets using a polynomial rolling hash.

    A single O(n) pass: a rolling hash is maintained over the trailing
    `config.GOLDEN_ROLLING_HASH_WINDOW` bytes, and a boundary is declared
    wherever its low bits match a mask sized for
    `config.GOLDEN_TARGET_CHUNK_SIZE` -- since the hash is a function of
    local content, not position, an insertion anywhere in the file only
    perturbs the boundaries immediately around it; every boundary further
    away is re-derived from the same (merely shifted) bytes and lands in
    the same place relative to that content.

    Args:
        data: Full contents of the file to chunk.

    Returns:
        Ascending list of chunk-end offsets (exclusive), covering the
        whole of `data` -- the last entry always equals `len(data)`.
        Empty list only for empty input.

    Raises:
        None.
    """
    length = len(data)
    if length == 0:
        return []

    window = config.GOLDEN_ROLLING_HASH_WINDOW
    min_size = config.GOLDEN_MIN_CHUNK_SIZE
    max_size = config.GOLDEN_MAX_CHUNK_SIZE
    target = config.GOLDEN_TARGET_CHUNK_SIZE

    # A mask with roughly log2(target) low bits set gives each rolling
    # hash value a 1-in-target chance of matching -- the standard content-
    # defined chunking construction.
    mask_bits = max(1, target.bit_length() - 1)
    chunk_mask = (1 << mask_bits) - 1

    base_pow_window = pow(_HASH_BASE, window, _HASH_MOD)

    boundaries: List[int] = []
    chunk_size = 0
    rolling_hash = 0

    for index in range(length):
        rolling_hash = (rolling_hash * _HASH_BASE + _GEAR_TABLE[data[index]]) % _HASH_MOD
        if index >= window:
            outgoing = data[index - window]
            rolling_hash = (rolling_hash - _GEAR_TABLE[outgoing] * base_pow_window) % _HASH_MOD
        chunk_size += 1

        has_full_window = index >= window - 1
        at_content_boundary = has_full_window and (rolling_hash & chunk_mask) == 0

        if chunk_size >= min_size and (at_content_boundary or chunk_size >= max_size):
            boundaries.append(index + 1)
            chunk_size = 0

    if not boundaries or boundaries[-1] != length:
        boundaries.append(length)

    return boundaries


def chunk_spans(data: bytes) -> List[Tuple[int, int]]:
    """Split a file's bytes into content-defined chunk (start, end) spans.

    Args:
        data: Full contents of the file to chunk.

    Returns:
        List of (start, end) tuples covering `data` with no gaps or
        overlaps. Empty list for empty input.

    Raises:
        None.
    """
    boundaries = _rolling_hash_boundaries(data)
    spans: List[Tuple[int, int]] = []
    start = 0
    for boundary in boundaries:
        spans.append((start, boundary))
        start = boundary
    return spans


def _hash_chunks(data: bytes, spans: List[Tuple[int, int]]) -> List[_Chunk]:
    """Compute the SHA-256 of every chunk span.

    Args:
        data: Full contents of the file the spans were cut from.
        spans: (start, end) tuples, as built by `chunk_spans()`.

    Returns:
        One `_Chunk` per span, in the same order.

    Raises:
        None.
    """
    return [
        _Chunk(start=start, end=end, sha256=hashlib.sha256(data[start:end]).hexdigest())
        for start, end in spans
    ]


def _classify_against_golden(
    chunk: _Chunk, golden_data: bytes
) -> Tuple[str, Optional[int], Optional[float]]:
    """Classify a changed suspect chunk against the golden reference by position.

    Chunks reaching this point already had no content match anywhere in
    golden (Layer 2 filtered those out), so a position-based lookup here
    is safe: it is only ever used to ask "what, if anything, occupied
    this same region of the clean firmware?", not to re-detect content
    that has merely shifted.

    Args:
        chunk: A suspect chunk whose hash was not found in golden.
        golden_data: Full contents of the golden reference.

    Returns:
        A (diff_type, golden_offset, golden_entropy) tuple. `diff_type`
        is "new" if the chunk lies entirely beyond golden's size (no
        counterpart at all), "grown" if it starts within golden's range
        but extends past golden's end, or "modified" if it lies entirely
        within golden's byte range. `golden_offset`/`golden_entropy` are
        None only for "new".

    Raises:
        None.
    """
    golden_length = len(golden_data)

    if chunk.start >= golden_length:
        return "new", None, None

    golden_slice_end = min(chunk.end, golden_length)
    golden_slice = golden_data[chunk.start:golden_slice_end]
    golden_entropy = shannon_entropy(golden_slice) if golden_slice else None

    if chunk.end > golden_length:
        return "grown", chunk.start, golden_entropy
    return "modified", chunk.start, golden_entropy


def _severity_for_diff(
    diff_type: str,
    suspect_entropy: float,
    entropy_transition: bool,
) -> Tuple[str, float]:
    """Determine severity and confidence for one golden-diff finding.

    Args:
        diff_type: "new", "modified", or "grown".
        suspect_entropy: Shannon entropy of the suspect chunk's bytes.
        entropy_transition: True if the golden counterpart was low
            entropy and the suspect content is high entropy -- the
            strongest injection signal this module produces.

    Returns:
        A (severity, confidence) tuple. `entropy_transition` always wins
        (critical) regardless of `diff_type`, matching the module's
        severity rules: a low-to-high entropy transition, backed by a
        clean reference, is unambiguous. `confidence` starts at
        `config.GOLDEN_DIFF_BASE_CONFIDENCE` and is nudged from there;
        Layer 4 structural corroboration (if any) is folded in
        separately by the caller, since it is only ever known after this
        finding already exists. Clamped to [0.0, 1.0].

    Raises:
        None.
    """
    confidence = config.GOLDEN_DIFF_BASE_CONFIDENCE
    high_entropy = suspect_entropy > config.GOLDEN_HIGH_ENTROPY_THRESHOLD
    low_entropy = suspect_entropy < config.GOLDEN_LOW_ENTROPY_THRESHOLD

    if entropy_transition:
        severity = "critical"
        confidence += 0.15
    elif diff_type == "grown":
        severity = "high"
    elif diff_type == "new":
        if high_entropy:
            severity = "high"
        elif low_entropy:
            severity = "low"
            confidence -= 0.2
        else:
            severity = "medium"
    else:  # "modified", no entropy transition
        severity = "medium"

    return severity, max(0.0, min(1.0, confidence))


def _describe_diff(
    diff_type: str,
    chunk: _Chunk,
    golden_offset: Optional[int],
    golden_entropy: Optional[float],
    suspect_entropy: float,
    entropy_transition: bool,
) -> str:
    """Build the human-readable description for one golden-diff finding.

    Args:
        diff_type: "new", "modified", or "grown".
        chunk: The suspect chunk this finding covers.
        golden_offset: Byte offset of the golden counterpart, or None.
        golden_entropy: Shannon entropy of the golden counterpart, or
            None.
        suspect_entropy: Shannon entropy of the suspect chunk.
        entropy_transition: True if this is a low-to-high entropy
            transition (see `_severity_for_diff()`).

    Returns:
        The description string.

    Raises:
        None.
    """
    size = chunk.end - chunk.start
    location = f"at offset {_hex(chunk.start)} ({size} bytes)"

    if diff_type == "new":
        return (
            f"New region in suspect with no counterpart in golden reference {location} "
            f"(entropy {suspect_entropy:.3f} bits/byte)"
        )

    golden_entropy_str = f"{golden_entropy:.3f}" if golden_entropy is not None else "n/a"
    if diff_type == "grown":
        return (
            f"Region grown beyond golden reference's size {location}, golden counterpart "
            f"at offset {_hex(golden_offset)} (suspect entropy {suspect_entropy:.3f}, "
            f"golden entropy {golden_entropy_str} bits/byte)"
        )

    verdict = (
        "low-entropy region in golden replaced with high-entropy content in suspect "
        "— possible payload injection"
        if entropy_transition
        else "content differs from the golden reference at the same position"
    )
    return (
        f"Modified region {location}, golden counterpart at offset {_hex(golden_offset)} "
        f"(suspect entropy {suspect_entropy:.3f}, golden entropy {golden_entropy_str} "
        f"bits/byte) — {verdict}"
    )


def _build_chunk_finding(chunk: _Chunk, golden_data: bytes, suspect_data: bytes) -> Finding:
    """Build the Finding for one changed/new suspect chunk (Layer 3).

    Args:
        chunk: A suspect chunk whose hash was not found in golden.
        golden_data: Full contents of the golden reference.
        suspect_data: Full contents of the suspect firmware.

    Returns:
        A scored Finding with the full raw dict described in the module
        docstring.

    Raises:
        None.
    """
    suspect_entropy = shannon_entropy(suspect_data[chunk.start:chunk.end])
    diff_type, golden_offset, golden_entropy = _classify_against_golden(chunk, golden_data)

    entropy_transition = (
        golden_entropy is not None
        and golden_entropy < config.GOLDEN_LOW_ENTROPY_THRESHOLD
        and suspect_entropy > config.GOLDEN_HIGH_ENTROPY_THRESHOLD
    )

    severity, confidence = _severity_for_diff(diff_type, suspect_entropy, entropy_transition)
    description = _describe_diff(
        diff_type, chunk, golden_offset, golden_entropy, suspect_entropy, entropy_transition
    )

    return Finding(
        module_name=MODULE_NAME,
        severity=severity,
        offset=chunk.start,
        description=description,
        evidence=f"confidence={confidence:.2f} suspect_entropy={suspect_entropy:.3f}",
        score=config.SEVERITY_SCORE_WEIGHTS[severity],
        raw={
            "diff_type": diff_type,
            "suspect_offset": chunk.start,
            "golden_offset": golden_offset,
            "suspect_entropy": suspect_entropy,
            "golden_entropy": golden_entropy,
            "entropy_transition": entropy_transition,
            "chunk_size": chunk.end - chunk.start,
            "source": MODULE_NAME,
            "confidence": confidence,
            "structural_diff": False,
        },
    )


def _structurally_novel_regions(
    golden_regions: List[BinwalkRegion], suspect_regions: List[BinwalkRegion]
) -> List[BinwalkRegion]:
    """Find suspect Binwalk regions with no positional counterpart in golden (Layer 4).

    Args:
        golden_regions: Regions Binwalk recognized in the golden reference.
        suspect_regions: Regions Binwalk recognized in the suspect firmware.

    Returns:
        Suspect regions whose description does not appear anywhere in
        golden at all, or only appears at offsets more than
        `config.GOLDEN_MAX_CHUNK_SIZE` bytes away -- a structure Binwalk
        recognizes in suspect that golden has no equivalent of nearby.

    Raises:
        None.
    """
    golden_offsets_by_description: Dict[str, List[int]] = {}
    for region in golden_regions:
        golden_offsets_by_description.setdefault(region.description, []).append(region.offset)

    tolerance = config.GOLDEN_MAX_CHUNK_SIZE
    novel: List[BinwalkRegion] = []
    for region in suspect_regions:
        nearby_golden_offsets = golden_offsets_by_description.get(region.description, [])
        has_nearby_counterpart = any(
            abs(region.offset - golden_offset) <= tolerance
            for golden_offset in nearby_golden_offsets
        )
        if not has_nearby_counterpart:
            novel.append(region)
    return novel


def _apply_structural_diff(
    findings: List[Finding], novel_regions: List[BinwalkRegion], suspect_data: bytes
) -> List[Finding]:
    """Fold Layer 4's structurally-novel regions into the findings list.

    A novel region whose offset already falls inside an existing Layer 3
    finding is marked with `structural_diff=True` on that finding (extra
    corroboration, not a duplicate finding). A novel region with no
    existing finding covering it becomes a new, standalone MEDIUM finding
    -- Binwalk recognized something in suspect with no golden counterpart
    nearby, but nothing about its entropy stood out on its own.

    Args:
        findings: Findings already built from Layers 2-3.
        novel_regions: Regions from `_structurally_novel_regions()`.
        suspect_data: Full contents of the suspect firmware (used to
            compute a representative entropy value for a standalone
            structural finding).

    Returns:
        `findings`, mutated in place and possibly extended, then returned
        for convenience.

    Raises:
        None.
    """
    for region in novel_regions:
        covering_finding = next(
            (
                finding
                for finding in findings
                if finding.raw["suspect_offset"]
                <= region.offset
                < finding.raw["suspect_offset"] + finding.raw["chunk_size"]
            ),
            None,
        )
        if covering_finding is not None:
            covering_finding.raw["structural_diff"] = True
            covering_finding.raw["confidence"] = min(
                1.0, covering_finding.raw["confidence"] + 0.1
            )
            covering_finding.description += " [also flagged by Binwalk structural diff]"
            continue

        window_end = min(region.offset + config.GOLDEN_TARGET_CHUNK_SIZE, len(suspect_data))
        region_entropy = shannon_entropy(suspect_data[region.offset:window_end])
        # Always MEDIUM: this finding exists purely because Binwalk found
        # a structurally novel region with no entropy signal of its own
        # (a novel region WITH an entropy signal already got folded into
        # an existing Layer 3 finding above, via `covering_finding`).
        severity = "medium"
        confidence = min(1.0, config.GOLDEN_DIFF_BASE_CONFIDENCE + 0.1)

        findings.append(
            Finding(
                module_name=MODULE_NAME,
                severity=severity,
                offset=region.offset,
                description=(
                    f"Structural diff: {region.description} recognized in suspect "
                    f"at offset {_hex(region.offset)} with no counterpart in golden "
                    "reference nearby"
                ),
                evidence=f"confidence={confidence:.2f} description={region.description!r}",
                score=config.SEVERITY_SCORE_WEIGHTS[severity],
                raw={
                    "diff_type": "new",
                    "suspect_offset": region.offset,
                    "golden_offset": None,
                    "suspect_entropy": region_entropy,
                    "golden_entropy": None,
                    "entropy_transition": False,
                    "chunk_size": window_end - region.offset,
                    "source": MODULE_NAME,
                    "confidence": confidence,
                    "structural_diff": True,
                },
            )
        )

    return findings


def analyze_diff(golden_path: str, suspect_path: str) -> List[Finding]:
    """Compare suspect firmware against a clean golden reference.

    Args:
        golden_path: Path to a known-clean reference firmware image.
        suspect_path: Path to the firmware image being analyzed.

    Returns:
        Findings for regions present, modified, or grown in suspect but
        not in golden. Empty list if the two images have identical
        content (chunk-for-chunk and structurally).

    Raises:
        FileNotFoundError: If either file does not exist.
        AnalysisError: If either file cannot be read.
    """
    golden = Path(golden_path)
    suspect = Path(suspect_path)
    if not golden.is_file():
        raise FileNotFoundError(f"Golden reference firmware not found: {golden_path}")
    if not suspect.is_file():
        raise FileNotFoundError(f"Suspect firmware not found: {suspect_path}")

    try:
        golden_data = golden.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read golden reference {golden_path}: {exc}") from exc
    try:
        suspect_data = suspect.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read suspect firmware {suspect_path}: {exc}") from exc

    logger.info(
        "Golden diff: golden=%s (%d bytes), suspect=%s (%d bytes)",
        golden,
        len(golden_data),
        suspect,
        len(suspect_data),
    )

    golden_chunks = _hash_chunks(golden_data, chunk_spans(golden_data))
    suspect_chunks = _hash_chunks(suspect_data, chunk_spans(suspect_data))

    golden_hashes = {chunk.sha256 for chunk in golden_chunks}
    changed_chunks = [chunk for chunk in suspect_chunks if chunk.sha256 not in golden_hashes]
    unchanged_count = len(suspect_chunks) - len(changed_chunks)
    logger.info(
        "Chunk diff: %d suspect chunks, %d unchanged (in golden), %d changed/new",
        len(suspect_chunks),
        unchanged_count,
        len(changed_chunks),
    )

    findings = [
        _build_chunk_finding(chunk, golden_data, suspect_data) for chunk in changed_chunks
    ]

    try:
        golden_regions = binwalk_wrapper.scan_file(golden)
        suspect_regions = binwalk_wrapper.scan_file(suspect)
    except (FileNotFoundError, AnalysisError) as exc:
        logger.warning("Binwalk structural diff (Layer 4) unavailable, continuing without it: %s", exc)
        golden_regions, suspect_regions = [], []

    if suspect_regions:
        novel_regions = _structurally_novel_regions(golden_regions, suspect_regions)
        findings = _apply_structural_diff(findings, novel_regions, suspect_data)

    findings.sort(key=lambda finding: finding.offset if finding.offset is not None else 0)
    logger.info("Golden diff complete: %d finding(s)", len(findings))
    return findings


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Compare a suspect firmware image against a clean golden reference."
    )
    parser.add_argument("--golden", required=True, help="Path to the clean reference firmware")
    parser.add_argument("--suspect", required=True, help="Path to the firmware being analyzed")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    cli_args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if cli_args.verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )

    try:
        diff_findings = analyze_diff(cli_args.golden, cli_args.suspect)
    except FileNotFoundError as not_found_exc:
        logger.error("%s", not_found_exc)
        sys.exit(1)
    except AnalysisError as analysis_exc:
        logger.error("Golden diff failed: %s", analysis_exc)
        sys.exit(1)

    if not diff_findings:
        print("No differences found between golden and suspect firmware.")
    else:
        print(f"Detected {len(diff_findings)} difference(s):")
        for diff_finding in diff_findings:
            print(
                f"  [{diff_finding.severity.upper()}] offset={diff_finding.offset} "
                f"score={diff_finding.score} - {diff_finding.description}"
            )
