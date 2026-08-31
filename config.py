"""Global configuration for the HexWarden firmware analysis toolkit.

Centralizes every tunable threshold, severity-to-score weight mapping, and
module enable/disable flag used across the analysis pipeline. No module
should hardcode a magic number that affects analysis behavior; instead it
should import the relevant constant from this file.

Inputs:
    None. This module only defines constants.

Outputs:
    Module-level constants consumed by `core/`, `modules/`, and `main.py`.
"""

from pathlib import Path
from typing import List

# --------------------------------------------------------------------------
# General paths
# --------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR: Path = PROJECT_ROOT / "output"

# --------------------------------------------------------------------------
# Entropy analysis (modules/entropy.py)
# --------------------------------------------------------------------------
ENTROPY_WINDOW_SIZE: int = 256  # bytes sampled per sliding-window measurement
ENTROPY_STEP_SIZE: int = 64  # byte offset step between successive windows

# Severity thresholds for Shannon entropy scores, in bits/byte (0.0 - 8.0).
# Values below ENTROPY_THRESHOLD_LOW are considered normal code/data and
# are not reported as findings.
ENTROPY_THRESHOLD_LOW: float = 6.5  # slightly elevated, could be compressed data
ENTROPY_THRESHOLD_MEDIUM: float = 7.2  # likely compressed, possibly encrypted
ENTROPY_THRESHOLD_HIGH: float = 7.6  # probably encrypted payload
ENTROPY_THRESHOLD_CRITICAL: float = 7.9  # almost certainly encrypted - strong trojan indicator
ENTROPY_MAX_VALUE: float = 8.0  # theoretical maximum Shannon entropy for byte data

# --------------------------------------------------------------------------
# Severity -> risk score weight mapping (used by core/scoring.py)
# --------------------------------------------------------------------------
SEVERITY_SCORE_WEIGHTS: dict = {
    "info": 0,
    "low": 10,
    "medium": 35,
    "high": 65,
    "critical": 90,
}

# --------------------------------------------------------------------------
# Overall verdict thresholds (used by core/scoring.py), on a 0-100 scale
# --------------------------------------------------------------------------
RISK_VERDICT_SUSPICIOUS_THRESHOLD: int = 40  # combined score above this -> "suspicious"
RISK_VERDICT_MALICIOUS_THRESHOLD: int = 75  # combined score above this -> "malicious"

# --------------------------------------------------------------------------
# Module enable/disable flags
# --------------------------------------------------------------------------
ENABLED_MODULES: dict = {
    "entropy": True,
    "strings": False,
    "imports": False,
    "yara_engine": False,
    "crypto_constants": False,
    "filesystem": False,
    "network_monitor": False,
    "syscall_tracer": False,
    "pipeline": True,
}

# --------------------------------------------------------------------------
# CLI output (main.py)
# --------------------------------------------------------------------------
CLI_SUMMARY_TOP_N: int = 10  # highest-score findings printed to the terminal by default

# --------------------------------------------------------------------------
# Binwalk recursive extraction pipeline
# (modules/binwalk_wrapper.py, modules/firmware_pipeline.py)
# --------------------------------------------------------------------------
# Path to the binwalk system binary used by the subprocess backend.
# Change this if binwalk is installed elsewhere (e.g. /usr/local/bin/binwalk).
# To use the Python API backend instead, install binwalk as a package:
#   git clone https://github.com/ReFirmLabs/binwalk && cd binwalk && pip install .
BINWALK_BINARY: str = "/usr/bin/binwalk"
BINWALK_SUBPROCESS_TIMEOUT_SECONDS: int = 300  # safety cap for large firmware extraction

# Binwalk's plain-text scan table never reports a region's size, so an end
# offset is inferred as the start of the next region (of the same kind) in
# offset order; the highest-offset region has no "next" region to bound it,
# so this fixed estimate is used as its extent instead.
BINWALK_LAST_REGION_SIZE_ESTIMATE: int = 1024 * 1024  # 1MB

BINWALK_EXTRACTION_DIR: Path = DEFAULT_OUTPUT_DIR / "extracted"  # matryoshka extraction root
EXTRACTED_SCAN_ENABLED: bool = True  # walk and analyze Binwalk's extracted contents

EXTRACTED_MIN_FILE_SIZE: int = 64  # bytes; smaller files are almost certainly padding
EXTRACTED_MAX_DEPTH: int = 10  # safety valve: stop walking beyond this many nested directories
EXTRACTED_SMALL_BLOB_MAX_SIZE: int = 512 * 1024  # bytes; "small encrypted blob" escalation cutoff

# A real firmware extraction tree can contain thousands of files, each
# requiring its own binwalk subprocess invocation (scan_file()) to
# cross-reference; running these one at a time is impractically slow
# (each call spends nearly all its time waiting on the subprocess, not
# holding Python's GIL), so the walk parallelizes them across this many
# worker threads.
EXTRACTED_SCAN_WORKERS: int = 8

# Path substrings (checked against a file's location relative to the
# extraction root) used by firmware_pipeline.py's severity escalation
# rules for unrecognized, high-entropy extracted files. "/." also matches
# hidden dotfiles anywhere in the path (e.g. "/home/.hidden").
SUSPICIOUS_LOCATIONS: List[str] = ["/tmp/", "/var/tmp/", "/dev/", "/."]
CONFIG_DATA_LOCATIONS: List[str] = ["/etc/", "/var/"]  # config/data should not be high-entropy
COMPILED_CODE_LOCATIONS: List[str] = ["/bin/", "/lib/"]  # compiled code can legitimately be

# Expected Shannon entropy range (bits/byte, min, max) for each recognized
# format, used by firmware_pipeline.py to tell "expected" high entropy
# (e.g. a compressed blob) apart from a "format anomaly" (e.g. a filesystem
# image with far more entropy than plain data should have -- contents may
# be encrypted). Matched by checking whether a keyword appears anywhere in
# a Binwalk description string (case-insensitive); the first match wins.
FORMAT_ENTROPY_RANGES: dict = {
    "xz": (7.8, 8.0),
    "gzip": (7.7, 8.0),
    "lzma": (7.7, 8.0),
    "zlib": (7.5, 8.0),
    "squashfs": (7.5, 8.0),
    "ext2": (4.0, 7.5),
    "ext3": (4.0, 7.5),
    "ext4": (4.0, 7.5),
    "zip": (7.5, 8.0),
    "elf": (4.0, 6.8),
    "pe": (4.0, 6.8),
    "jffs2": (6.0, 8.0),
    "cramfs": (7.0, 8.0),
    "certificate": (7.0, 8.0),
    "private key": (7.5, 8.0),
}

# --------------------------------------------------------------------------
# Context-aware entropy detection (modules/entropy.py, modules/firmware_pipeline.py)
#
# Replaces the old global-threshold "flag everything above X bits/byte"
# approach: a high-entropy region is only a candidate finding if it is
# anomalous relative to its own local neighborhood (or the whole file is
# uniformly high-entropy with no format explanation at all), and its
# severity is derived from a continuous confidence score built from
# several corroborating signals rather than entropy value alone.
# --------------------------------------------------------------------------

# Local contrast analysis (modules/entropy.py's compute_local_contrast).
ENTROPY_NEIGHBORHOOD_BYTES: int = 65536  # neighborhood radius, each side, in bytes
ENTROPY_ADAPTIVE_IQR_MULTIPLIER: float = 3.5  # sample must exceed median by this many IQRs
ENTROPY_LOCAL_ANOMALY_MIN_DELTA: float = 2.5  # ...and by at least this many bits, in absolute terms
# Calibrated against a real ~184MB Linux firmware image (hundreds of ELF
# binaries): the illustrative defaults (2.0 IQRs / 1.0 bit) flag 1000+
# regions on real firmware of this size and complexity -- every binary's
# symbol table, hash table, and small embedded data structures locally
# exceed their neighborhood's entropy by design, not because anything was
# injected. Raising both bars cuts that substantially without touching
# the underlying local-contrast *method*, only its sensitivity -- exactly
# what these two constants exist to be tuned for.

# A full-resolution sliding-window median/IQR (one evaluation per entropy
# sample) is prohibitively slow on large firmware -- benchmarked at ~110s
# for a 184MB image's ~2.9M samples. Since the neighborhood (above) is far
# wider than the per-sample step, consecutive samples' neighborhoods barely
# differ, so the window statistics are instead evaluated every this-many
# samples and linearly interpolated for the samples in between (~6.6s for
# the same firmware at the default stride, with negligible accuracy loss).
ENTROPY_LOCAL_CONTRAST_STRIDE: int = 16

# Global whole-file check (modules/firmware_pipeline.py): catches a file
# with no internal contrast because it is uniformly encrypted throughout.
ENTROPY_GLOBAL_SUSPICIOUS_MEDIAN: float = 7.8

# Entropy boundary/transition detection (modules/entropy.py's
# detect_entropy_transitions): a rising-then-falling entropy step of at
# least this many bits, within ENTROPY_PAYLOAD_SIZE_MAX bytes of each
# other, is a sharp "spike and return" -- the fingerprint of an injected
# payload rather than a gradual code/data boundary.
ENTROPY_TRANSITION_DELTA: float = 1.5

# Chi-square uniformity test (modules/entropy.py's chi_square_uniformity):
# the chi-square statistic of a region's byte-value histogram against a
# uniform distribution. Below this threshold the distribution reads as
# "encryption-like" (near-perfectly uniform); above it, structure remains
# and it reads as "compression-like". A second band, further above (see
# CHI_SQUARE_STRUCTURED_MULTIPLIER), reads as "structured" -- clearly
# patterned data, not really random/compressed at all.
CHI_SQUARE_ENCRYPTED_THRESHOLD: float = 300.0  # tune against real data; lower = more uniform
CHI_SQUARE_STRUCTURED_MULTIPLIER: float = 3.0  # "structured" starts at this many x the threshold

# Size as a confidence weight, never a filter (modules/firmware_pipeline.py).
ENTROPY_PAYLOAD_SIZE_MIN: int = 1024  # bytes; below this, likely a hash/key/padding, not a payload
ENTROPY_PAYLOAD_SIZE_MAX: int = 1024 * 1024  # bytes; above this, likely a legitimate large blob

# Confidence -> severity thresholds (modules/firmware_pipeline.py).
CONFIDENCE_CRITICAL: float = 0.85
CONFIDENCE_HIGH: float = 0.65
CONFIDENCE_MEDIUM: float = 0.45

# Confidence scoring weights (modules/firmware_pipeline.py). A local-anomaly
# candidate starts from CONFIDENCE_LOCAL_ANOMALY_BASE; a whole-file
# candidate (which by definition has no local neighborhood to stand out
# from) starts higher, matching its "HIGH candidate" framing. Each signal
# then nudges the score up or down; the result is clamped to [0.0, 1.0].
CONFIDENCE_LOCAL_ANOMALY_BASE: float = 0.40
CONFIDENCE_WHOLE_FILE_BASE: float = 0.70
CONFIDENCE_TRANSITION_BOOST: float = 0.25  # sharp spike-and-return boundary detected
CONFIDENCE_ENCRYPTION_LIKE_BOOST: float = 0.20  # byte distribution reads as near-uniform
CONFIDENCE_COMPRESSION_LIKE_PENALTY: float = 0.10  # distribution has residual/compression structure
CONFIDENCE_PAYLOAD_SIZE_BOOST: float = 0.15  # region size falls in the "real payload" range
# Size-mismatch penalties are asymmetric: a "small" region is both more
# confidently benign (spec: "likely a hash/key/padding") AND the
# chi-square uniformity test loses statistical power below a few hundred
# bytes (expected count per byte-value bin drops well under the ~5
# textbook minimum for the chi-square approximation to hold), so a small
# region reading as "encryption-like" is itself less trustworthy -- a
# larger blob's "wrong size for a payload" is a weaker, single signal by
# comparison.
CONFIDENCE_SMALL_SIZE_PENALTY: float = 0.30  # region is below ENTROPY_PAYLOAD_SIZE_MIN
CONFIDENCE_LARGE_SIZE_PENALTY: float = 0.15  # region is above ENTROPY_PAYLOAD_SIZE_MAX

# --------------------------------------------------------------------------
# Pipeline entropy plot (modules/entropy.py's generate_pipeline_plot)
# --------------------------------------------------------------------------
PLOT_FORMAT_LABEL_MAX_CHARS: int = 15  # region label truncation, e.g. "Expected: [...]"
PLOT_FILENAME_LABEL_MAX_CHARS: int = 20  # extracted-file boundary label truncation

# A real extraction tree can contain thousands of files; marking every one
# with a boundary line + rotated filename label produces an illegible solid
# black mass where files sit close together on the x-axis. Consecutive
# extraction-boundary labels are thinned to at least this fraction of the
# plot's total x-axis span apart (the dotted line and filename label are
# skipped for files closer than that to the last labeled one -- every
# file's entropy curve and finding highlights are still drawn regardless).
PLOT_MIN_BOUNDARY_LABEL_SPACING_FRACTION: float = 0.03

# Known magic byte sequences checked against the first bytes of a file
# when Binwalk itself does not recognize the format.
MAGIC_HEADERS: dict = {
    "ELF": bytes([0x7F, 0x45, 0x4C, 0x46]),
    "PE": bytes([0x4D, 0x5A]),
    "gzip": bytes([0x1F, 0x8B]),
    "SquashFS": bytes([0x68, 0x73, 0x71, 0x73]),
    "LZMA": bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]),
    "zlib": bytes([0x78, 0x9C]),
    "ZIP": bytes([0x50, 0x4B, 0x03, 0x04]),
    "PNG": bytes([0x89, 0x50, 0x4E, 0x47]),
}

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
LOG_FORMAT: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_LEVEL: str = "INFO"
