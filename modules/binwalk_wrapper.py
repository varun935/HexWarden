"""Binwalk integration wrapper for HexWarden.

Wraps Binwalk to provide recursive ("matryoshka") firmware extraction and
per-file format recognition. Every Binwalk invocation in the codebase is
funneled through this module so the rest of the toolkit never talks to
Binwalk directly.

Inputs:
    Firmware file paths (str/Path) for scanning/extraction, and raw byte
    prefixes for magic-header checks.

Outputs:
    `BinwalkResult` / `BinwalkRegion` dataclasses describing what Binwalk
    recognized in a binary and where (if anywhere) it extracted content.

# ── Backend detection ──────────────────────────────────────────────────────
# HexWarden supports two Binwalk backends:
#
#   API backend  — uses `import binwalk` (Binwalk installed as a Python
#                  package). Cleaner, no subprocess overhead, structured
#                  result objects. Requires:
#                      git clone https://github.com/ReFirmLabs/binwalk
#                      cd binwalk && pip install .
#                  To switch to this backend: install as above. The code
#                  detects it automatically via the try/except below —
#                  no code changes needed.
#
#   Subprocess   — calls /usr/bin/binwalk as a shell process and parses
#   backend        its stdout. Works with `apt install binwalk`. This is
#                  the default because it requires no Python package setup.
#                  Currently active backend (API not available).
#
# To switch backends: install the Python API (see above). On next run
# the try/except below will succeed and the API backend activates
# automatically. No config changes, no code changes needed.
# ──────────────────────────────────────────────────────────────────────────
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import config
from core import AnalysisError

logger = logging.getLogger(__name__)

try:
    import binwalk as _binwalk_api

    _BACKEND = "api"
except ImportError:
    _binwalk_api = None
    _BACKEND = "subprocess"

# The API backend is detected above for forward compatibility (see the
# module banner), but is not actually invoked anywhere in this module --
# the subprocess backend is the ONLY backend used for now. All real
# Binwalk invocations below go through config.BINWALK_BINARY.
_BINWALK_BINARY_PATH = shutil.which(config.BINWALK_BINARY)
_BINWALK_AVAILABLE = _BINWALK_BINARY_PATH is not None
_BINWALK_IMPORT_ERROR: Optional[Exception] = (
    None
    if _BINWALK_AVAILABLE
    else FileNotFoundError(f"binwalk binary not found or not executable: {config.BINWALK_BINARY}")
)

# Substrings of a Binwalk description that indicate a known compression or
# archive format, as opposed to e.g. a plain string/copyright/hash-table
# signature match.
_COMPRESSION_DESCRIPTION_KEYWORDS = (
    "compressed",
    "squashfs",
    "filesystem",
    "archive",
    "zip",
    "gzip",
    "lzma",
    "xz",
    "zlib",
    "cramfs",
    "jffs2",
)


@dataclass
class BinwalkRegion:
    """A single region of a binary that Binwalk recognized.

    Attributes:
        offset: Byte offset in the scanned file where the region starts.
        size: Size of the region in bytes, or None if Binwalk did not
            report a size for this signature match (the subprocess
            backend's plain-text table never reports a size, so this is
            always None for regions it produces).
        description: Binwalk's human-readable identification string.
        is_compression: True if `description` matches a known
            compression or archive format.
    """

    offset: int
    size: Optional[int]
    description: str
    is_compression: bool


@dataclass
class BinwalkResult:
    """Result of running recursive Binwalk extraction on a firmware file.

    Attributes:
        known_regions: Regions Binwalk identified in the top-level binary.
        extracted_dir: Root directory of all extracted contents, or None
            if Binwalk did not extract anything.
    """

    known_regions: List[BinwalkRegion] = field(default_factory=list)
    extracted_dir: Optional[Path] = None


def _require_binwalk() -> None:
    """Raise AnalysisError if the subprocess backend's binary is unusable.

    Args:
        None.

    Returns:
        None.

    Raises:
        AnalysisError: If `config.BINWALK_BINARY` could not be found or
            is not executable.
    """
    if not _BINWALK_AVAILABLE:
        raise AnalysisError(
            "Binwalk is not available via the subprocess backend "
            f"({_BINWALK_IMPORT_ERROR}). Install it with 'apt install binwalk' "
            "(or point config.BINWALK_BINARY at its install path). Falling "
            "back to raw entropy analysis only."
        )


def _is_compression_description(description: str) -> bool:
    """Check whether a Binwalk description string names a known compression/archive format.

    Args:
        description: Binwalk's human-readable identification string.

    Returns:
        True if any known compression/archive keyword appears in
        `description` (case-insensitive).

    Raises:
        None.
    """
    lowered = description.lower()
    return any(keyword in lowered for keyword in _COMPRESSION_DESCRIPTION_KEYWORDS)


def _run_binwalk(args: List[str]) -> subprocess.CompletedProcess:
    """Invoke the configured binwalk binary and capture its output.

    Never passes a `cwd` override to the subprocess: callers must pass
    fully resolved, absolute paths in `args` instead. Combining a
    relative path with a `cwd` override previously caused binwalk to be
    given a doubled path (e.g. a path already relative to `cwd` resolved
    a second time against it) and silently find nothing.

    Args:
        args: CLI arguments to pass to binwalk (flags and/or an absolute
            firmware path).

    Returns:
        The completed subprocess result. A non-zero `returncode` is
        returned as-is, not raised -- callers decide how to treat it.

    Raises:
        AnalysisError: If the binwalk binary cannot be executed at all
            (e.g. removed after the availability check, a permissions
            error) or the run exceeds `config.BINWALK_SUBPROCESS_TIMEOUT_SECONDS`.
    """
    command = [config.BINWALK_BINARY, *args]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=config.BINWALK_SUBPROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AnalysisError(f"Failed to run binwalk ({' '.join(command)}): {exc}") from exc

    # Binwalk is noisy on stderr (extractor warnings, missing external
    # tools, etc.) even on a successful run; keep it out of normal logs.
    if completed.stderr:
        logger.debug("binwalk stderr (%s): %s", " ".join(command), completed.stderr.strip())

    return completed


def _parse_scan_output(stdout_text: str) -> List[BinwalkRegion]:
    """Parse binwalk's plain-text scan table into BinwalkRegion objects.

    Handles both the plain scan-only table ("DECIMAL / HEXADECIMAL /
    DESCRIPTION" header, then data rows) and the extended preamble
    binwalk prints in extraction mode ("Scan Time:", "Target File:",
    "MD5 Checksum:", "Signatures:" lines before the same table), by
    simply treating any line whose first whitespace-separated field is
    not a plain decimal integer as non-data, rather than assuming a
    fixed number of header lines.

    Args:
        stdout_text: Captured stdout from a binwalk invocation.

    Returns:
        List of BinwalkRegion objects, one per data row, in the order
        binwalk printed them. Empty list if no data rows were found.

    Raises:
        None.
    """
    regions: List[BinwalkRegion] = []
    for line in stdout_text.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) < 3:
            continue
        try:
            offset = int(parts[0])
        except ValueError:
            continue
        description = parts[2]
        regions.append(
            BinwalkRegion(
                offset=offset,
                size=None,
                description=description,
                is_compression=_is_compression_description(description),
            )
        )
    return regions


def extract(filepath: str, output_dir: Path) -> BinwalkResult:
    """Run Binwalk with recursive (matryoshka) extraction on a firmware file.

    The subprocess backend extracts into Binwalk's own fixed
    "_<firmware_filename>.extracted" directory; where Binwalk places it
    depends on the firmware's location relative to the current process's
    working directory (verified against the installed binary): next to
    the firmware file when the firmware sits inside the working
    directory's tree, but directly in the working directory when the
    firmware lies outside it. Both candidate locations are checked.
    `output_dir` is accepted for interface compatibility but not used to
    place output.

    Args:
        filepath: Path to the firmware binary to extract.
        output_dir: Unused by the subprocess backend (kept for interface
            compatibility with callers).

    Returns:
        `BinwalkResult` describing the regions Binwalk recognized in the
        top-level binary and the root directory of extracted content
        (`extracted_dir` is None if nothing was extracted).

    Raises:
        FileNotFoundError: If `filepath` does not exist.
        AnalysisError: If Binwalk is unavailable or the subprocess fails
            to run at all.
    """
    logger.info("Binwalk backend: %s", _BACKEND.upper())
    _require_binwalk()

    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")
    resolved_path = path.resolve()

    completed = _run_binwalk(["--extract", "--matryoshka", str(resolved_path)])

    known_regions: List[BinwalkRegion] = []
    if completed.returncode != 0:
        logger.warning(
            "binwalk exited with code %d while extracting %s; treating as no known regions",
            completed.returncode,
            resolved_path,
        )
    else:
        known_regions = _parse_scan_output(completed.stdout)

    # Binwalk names the extraction directory after the target's basename,
    # but *where* it places it is inconsistent (see the docstring note
    # above), so check both locations it has been observed to use.
    extraction_dir_name = f"_{resolved_path.name}.extracted"
    candidate_dirs = (
        resolved_path.parent / extraction_dir_name,
        Path.cwd() / extraction_dir_name,
    )
    extracted_dir = next((candidate for candidate in candidate_dirs if candidate.is_dir()), None)

    logger.info(
        "Binwalk found %d known region(s) in %s; extracted_dir=%s",
        len(known_regions),
        resolved_path,
        extracted_dir,
    )
    return BinwalkResult(known_regions=known_regions, extracted_dir=extracted_dir)


def scan_file(filepath: Path) -> List[BinwalkRegion]:
    """Run a Binwalk signature scan (no extraction) on a single file.

    Args:
        filepath: Path to the file to scan.

    Returns:
        List of recognized regions. An empty list means Binwalk found
        nothing recognizable in the file (or the scan itself failed) --
        the "not recognizable" case used by the pipeline to fall back to
        a magic-header check and, ultimately, entropy analysis.

    Raises:
        FileNotFoundError: If `filepath` does not exist.
        AnalysisError: If Binwalk is unavailable or the subprocess fails
            to run at all.
    """
    _require_binwalk()

    if not filepath.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")
    resolved_path = filepath.resolve()

    completed = _run_binwalk([str(resolved_path)])

    if completed.returncode != 0:
        logger.warning(
            "binwalk exited with code %d while scanning %s; treating as unrecognized",
            completed.returncode,
            resolved_path,
        )
        return []

    return _parse_scan_output(completed.stdout)


def is_expected_compression(offset: int, size: int, known_regions: List[BinwalkRegion]) -> bool:
    """Check whether a byte range overlaps a known compression/archive region.

    Binwalk's plain-text scan table never reports a region's size (see
    `_parse_scan_output`), so a region's end offset can't simply be read
    off it. Instead, compression-flagged regions are sorted by offset and
    each one's end is inferred as the start of the next compression
    region; the last (highest-offset) region has no next region to bound
    it, so `config.BINWALK_LAST_REGION_SIZE_ESTIMATE` is used instead. A
    region that *does* report an explicit size (e.g. a future backend)
    uses that size directly rather than the inferred extent.

    Args:
        offset: Start offset of the byte range to check (e.g. an entropy
            finding's start offset).
        size: Length of the byte range in bytes.
        known_regions: Regions Binwalk identified, typically from
            `BinwalkResult.known_regions`.

    Returns:
        True if the half-open range [offset, offset + size) overlaps any
        compression/archive region in `known_regions`, using the overlap
        condition `region_start <= offset < region_end` or
        `region_start < finding_end <= region_end`.

    Raises:
        None.
    """
    compression_regions = sorted(
        (region for region in known_regions if region.is_compression),
        key=lambda region: region.offset,
    )
    if not compression_regions:
        return False

    finding_end = offset + size
    for index, region in enumerate(compression_regions):
        region_start = region.offset
        if region.size is not None:
            region_end = region_start + region.size
        elif index + 1 < len(compression_regions):
            region_end = compression_regions[index + 1].offset
        else:
            region_end = region_start + config.BINWALK_LAST_REGION_SIZE_ESTIMATE

        if (region_start <= offset < region_end) or (region_start < finding_end <= region_end):
            return True
    return False


def check_magic_header(data: bytes) -> Optional[str]:
    """Check a byte prefix against the configured table of magic headers.

    Args:
        data: The first bytes of a file (at least 8 bytes recommended).

    Returns:
        The recognized format name (e.g. "ELF", "gzip"), or None if no
        configured magic header matches.

    Raises:
        None.
    """
    for name, magic in config.MAGIC_HEADERS.items():
        if data[: len(magic)] == magic:
            return name
    return None


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Run a Binwalk signature scan (no extraction) on a firmware file."
    )
    parser.add_argument("firmware", help="Path to firmware binary file")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)

    try:
        found_regions = scan_file(Path(args.firmware))
    except (FileNotFoundError, AnalysisError) as scan_exc:
        logger.error("%s", scan_exc)
        sys.exit(1)

    if not found_regions:
        print("No recognizable regions found.")
    else:
        print(f"Found {len(found_regions)} recognized region(s):")
        for found_region in found_regions:
            print(f"  offset={found_region.offset} {found_region.description}")
