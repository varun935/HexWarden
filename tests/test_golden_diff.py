"""Unit tests for modules/golden_diff.py.

Exercises the four-layer golden-image diff: content-defined chunking's
core robustness property (a shifted-but-otherwise-identical firmware only
flags the region actually touched by an insertion, not everything
downstream of it), the hash-based block diff dropping unchanged content
instantly, and the entropy-comparison severity rules -- a low-entropy
golden region replaced by high-entropy suspect content is a CRITICAL
injection signature, a brand-new low-entropy addition is LOW, and a
modified region whose entropy stays similar is MEDIUM rather than
CRITICAL.

Inputs:
    None directly (pytest fixtures create temporary golden/suspect
    firmware files on disk; `monkeypatch` stubs out Binwalk's structural
    scan so these tests exercise Layers 1-3 deterministically without
    depending on a real Binwalk install).

Outputs:
    None (test assertions; pytest reports pass/fail).
"""

import random
from pathlib import Path

import pytest

import config
from modules import binwalk_wrapper, golden_diff

# A deterministic peak-entropy-8.0 blob: every 256-byte window contains
# exactly one of each possible byte value. Used wherever a test needs
# reliable, reproducible high-entropy content.
_HIGH_ENTROPY_BLOB = (bytes(range(256)) * 32) * 4  # 32768 bytes


def _prng_bytes(size: int, seed: int = 42) -> bytes:
    """Deterministic pseudo-random bytes -- statistically realistic firmware-like
    content without the exact periodicity of a literal repeating pattern,
    and reproducible across test runs (unlike os.urandom()).
    """
    return random.Random(seed).randbytes(size)


@pytest.fixture(autouse=True)
def _stub_binwalk_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub out Binwalk's structural scan (Layer 4) for every test in this file.

    Isolates these tests to Layers 1-3 (chunking, hash diff, entropy
    comparison) and removes any dependency on a real Binwalk install.

    Args:
        monkeypatch: Pytest fixture used to patch `binwalk_wrapper.scan_file`.

    Returns:
        None.

    Raises:
        None.
    """
    monkeypatch.setattr(binwalk_wrapper, "scan_file", lambda filepath: [])


def _write_pair(tmp_path: Path, golden_data: bytes, suspect_data: bytes) -> tuple:
    """Write golden/suspect firmware files and return their paths."""
    golden_path = tmp_path / "golden.bin"
    suspect_path = tmp_path / "suspect.bin"
    golden_path.write_bytes(golden_data)
    suspect_path.write_bytes(suspect_data)
    return golden_path, suspect_path


def test_identical_golden_and_suspect_produce_zero_findings(tmp_path: Path) -> None:
    """Byte-identical golden and suspect firmware yield no findings at all.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If any finding is produced for identical input.
    """
    data = b"\x00" * 20000 + _prng_bytes(10000) + b"\xAA" * 20000
    golden_path, suspect_path = _write_pair(tmp_path, data, data)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    assert findings == []


def test_injected_high_entropy_blob_is_critical_with_entropy_transition(
    tmp_path: Path,
) -> None:
    """A high-entropy blob replacing a low-entropy golden region is a CRITICAL injection signature.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no CRITICAL finding with entropy_transition=True
            is produced.
    """
    golden = b"\x00" * 200000
    suspect = b"\x00" * 80000 + _HIGH_ENTROPY_BLOB + b"\x00" * (
        len(golden) - 80000 - len(_HIGH_ENTROPY_BLOB)
    )
    assert len(suspect) == len(golden)
    golden_path, suspect_path = _write_pair(tmp_path, golden, suspect)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    critical_findings = [f for f in findings if f.severity == "critical"]
    assert critical_findings, "expected at least one CRITICAL finding"
    assert all(f.raw["entropy_transition"] is True for f in critical_findings)
    assert all(f.raw["diff_type"] == "modified" for f in critical_findings)
    assert all(f.raw["source"] == "golden_diff" for f in critical_findings)
    assert all(
        f.raw["confidence"] >= config.GOLDEN_DIFF_BASE_CONFIDENCE for f in critical_findings
    )


def test_chunking_robustness_shift_only_flags_the_injection(tmp_path: Path) -> None:
    """Inserting bytes at the start of suspect only flags the injection region.

    Proves the content-defined chunking actually works: a naive
    fixed-offset diff would flag the entire rest of the firmware as
    changed once everything shifts by the injected size, but chunk
    boundaries are content-defined, so downstream content re-aligns and
    still hashes to the same (unchanged) golden chunks.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If more than a small handful of findings are
            produced, or none are near the very start of the file.
    """
    base = _prng_bytes(150000)
    injected = b"MALICIOUS_PAYLOAD_" + bytes(range(256)) * 8  # 2067 bytes
    suspect = injected + base
    golden_path, suspect_path = _write_pair(tmp_path, base, suspect)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    # Not "the entire downstream firmware" -- a handful of chunks at most,
    # all clustered at the very start where the injection actually is.
    assert 1 <= len(findings) <= 3
    assert all(f.offset is not None and f.offset < len(injected) + 20000 for f in findings)


def test_new_low_entropy_addition_is_low_severity(tmp_path: Path) -> None:
    """A brand-new, low-entropy region appended to suspect is LOW severity, not critical.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no "new" LOW finding is produced, or any
            finding from this scenario is CRITICAL.
    """
    golden = b"\x00" * 50000
    suspect = golden + b"A" * 40000  # appended "config"-like low-entropy data
    golden_path, suspect_path = _write_pair(tmp_path, golden, suspect)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    new_low_findings = [
        f for f in findings if f.raw["diff_type"] == "new" and f.severity == "low"
    ]
    assert new_low_findings, "expected at least one new+low finding"
    assert not any(f.severity == "critical" for f in findings)


def test_modified_region_with_similar_entropy_is_medium_not_critical(tmp_path: Path) -> None:
    """A modified region whose entropy stays similar to golden's is MEDIUM, not CRITICAL.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no MEDIUM finding is produced, or any finding
            from this scenario is CRITICAL (there is no low-to-high
            entropy transition here -- both versions are moderate).
    """
    golden_mid = _prng_bytes(40000, seed=1)
    suspect_mid = _prng_bytes(40000, seed=2)  # different bytes, similar statistical entropy
    golden = b"\x00" * 80000 + golden_mid + b"\x00" * 80000
    suspect = b"\x00" * 80000 + suspect_mid + b"\x00" * 80000
    golden_path, suspect_path = _write_pair(tmp_path, golden, suspect)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    medium_findings = [f for f in findings if f.severity == "medium"]
    assert medium_findings, "expected at least one MEDIUM finding"
    assert not any(f.severity == "critical" for f in findings)
    assert all(f.raw["entropy_transition"] is False for f in medium_findings)


def test_golden_reference_not_found_raises_file_not_found_error(tmp_path: Path) -> None:
    """A missing golden reference raises FileNotFoundError with a clear message.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If FileNotFoundError is not raised, or its
            message doesn't identify the golden reference specifically.
    """
    suspect_path = tmp_path / "suspect.bin"
    suspect_path.write_bytes(b"\x00" * 1000)
    missing_golden = tmp_path / "does_not_exist.bin"

    with pytest.raises(FileNotFoundError, match="Golden reference"):
        golden_diff.analyze_diff(str(missing_golden), str(suspect_path))


def test_mismatched_firmware_sizes_handled_gracefully(tmp_path: Path) -> None:
    """Golden and suspect of very different total sizes are diffed without error.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If analyze_diff raises, or produces a finding
            whose offset lies outside the suspect firmware's own bounds.
    """
    golden = _prng_bytes(20000, seed=7)
    suspect = _prng_bytes(500000, seed=8)  # 25x larger, completely different content
    golden_path, suspect_path = _write_pair(tmp_path, golden, suspect)

    findings = golden_diff.analyze_diff(str(golden_path), str(suspect_path))

    assert len(findings) > 0
    assert all(0 <= (f.offset or 0) < len(suspect) for f in findings)
