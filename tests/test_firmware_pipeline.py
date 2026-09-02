"""Unit tests for modules/firmware_pipeline.py.

Exercises the pipeline's context-aware entropy detection: format-consistent
regions are dropped (never becoming a Finding), a region that stands out
from its local neighborhood becomes a candidate, a region inside an
already-uniformly-high-entropy neighborhood does not, an entire file with
no internal contrast and no format explanation is caught by the
independent whole-file check, and a format-claimed region whose entropy
falls outside its expected range still surfaces as a "format anomaly"
candidate. Also verifies the pipeline falls back to raw-entropy-only
findings without crashing when Binwalk is unavailable, and that its
mandatory extracted-directory cleanup runs without touching the original
firmware file.

Inputs:
    None directly (pytest fixtures create temporary firmware/extracted
    files on disk; `monkeypatch` simulates Binwalk availability/results).

Outputs:
    None (test assertions; pytest reports pass/fail).
"""

import hashlib
import os
from pathlib import Path

import pytest

import config
from modules import binwalk_wrapper, entropy, firmware_pipeline

# A repeating full byte-value permutation: every 256-byte sliding window
# contains exactly one of each possible byte value, giving a deterministic
# peak entropy of exactly 8.0 bits/byte -- unlike os.urandom(), whose
# per-window entropy at this window size tops out around 7.3 due to
# expected sampling collisions. Used wherever a test needs a reliable,
# reproducible high-entropy region.
_MAX_ENTROPY_BLOB = bytes(range(256)) * 64  # 16384 bytes, peak entropy 8.0


def _low_high_low_buffer(blob: bytes = _MAX_ENTROPY_BLOB, padding_size: int = 200_000) -> bytes:
    """Build a low-entropy buffer with a high-entropy blob embedded in the middle."""
    padding = b"\x00" * padding_size
    return padding + blob + padding


def _region(
    start: int, end: int, peak_entropy: float, median: float = 0.0, iqr: float = 0.1
) -> firmware_pipeline._CandidateRegion:
    """Build a synthetic candidate region for direct `_build_candidate_finding()` tests."""
    return firmware_pipeline._CandidateRegion(
        start_offset=start,
        end_offset=end,
        peak_entropy=peak_entropy,
        neighborhood_median=median,
        neighborhood_iqr=iqr,
        transition_anomaly=False,
    )


def test_format_consistent_region_is_dropped_not_a_finding() -> None:
    """A local-anomaly region whose entropy fits its recognized format is dropped entirely.

    Returns:
        None.

    Raises:
        AssertionError: If the region survives as a Finding, or the drop
            is not reflected in the summary counts.
    """
    data = _low_high_low_buffer()
    blob_start = 200_000
    blob_end = blob_start + len(_MAX_ENTROPY_BLOB)
    samples = entropy.compute_entropy_samples(data)
    known_regions = [
        binwalk_wrapper.BinwalkRegion(
            offset=blob_start,
            size=len(_MAX_ENTROPY_BLOB),
            description="gzip compressed data",
            is_compression=True,
        )
    ]

    findings, summary = firmware_pipeline._analyze_file_entropy(
        samples, data, known_regions, "firmware_pipeline", "raw_binary", None, None
    )

    assert findings == []
    assert summary.dropped_format_consistent >= 1
    assert summary.local_anomaly_candidates == 0
    assert summary.regions_analyzed == summary.dropped_format_consistent


def test_local_anomaly_in_low_entropy_neighborhood_produces_candidate() -> None:
    """A high-entropy region standing out from a low-entropy neighborhood becomes a candidate.

    Returns:
        None.

    Raises:
        AssertionError: If no candidate finding is produced, or it is not
            labeled as a local anomaly candidate.
    """
    data = _low_high_low_buffer()
    samples = entropy.compute_entropy_samples(data)

    findings, summary = firmware_pipeline._analyze_file_entropy(
        samples, data, [], "firmware_pipeline", "raw_binary", None, None
    )

    assert summary.local_anomaly_candidates >= 1
    assert len(findings) >= 1
    assert all(finding.raw["candidate"] is True for finding in findings)
    assert any(finding.raw["local_anomaly"] is True for finding in findings)
    assert any(finding.raw["recognized_format"] is None for finding in findings)


def test_high_entropy_region_in_uniform_neighborhood_is_not_a_local_anomaly() -> None:
    """A high-entropy region inside an already-uniformly-high-entropy neighborhood is not flagged.

    Returns:
        None.

    Raises:
        AssertionError: If local contrast flags any sample, or the
            pipeline reports any local-anomaly candidate.
    """
    data = _MAX_ENTROPY_BLOB * 32  # uniformly entropy 8.0 throughout, no internal contrast
    samples = entropy.compute_entropy_samples(data)

    contrast_results = entropy.compute_local_contrast(samples)
    assert not any(result.is_anomaly for result in contrast_results)

    _, summary = firmware_pipeline._analyze_file_entropy(
        samples, data, [], "firmware_pipeline", "raw_binary", None, None
    )
    assert summary.local_anomaly_candidates == 0
    assert summary.regions_analyzed == 0


def test_uniformly_high_entropy_file_with_no_format_is_whole_file_anomaly() -> None:
    """A uniformly high-entropy file with no Binwalk format explanation is a whole-file anomaly.

    Returns:
        None.

    Raises:
        AssertionError: If no whole-file anomaly finding is produced, or
            it is not labeled correctly.
    """
    data = _MAX_ENTROPY_BLOB * 32
    samples = entropy.compute_entropy_samples(data)

    findings, summary = firmware_pipeline._analyze_file_entropy(
        samples,
        data,
        [],
        "firmware_pipeline_extracted",
        "extracted",
        "/fake/blob.bin",
        "/blob.bin",
    )

    assert summary.whole_file_anomalies == 1
    whole_file_findings = [f for f in findings if f.raw.get("whole_file_anomaly")]
    assert len(whole_file_findings) == 1
    finding = whole_file_findings[0]
    assert finding.raw["local_anomaly"] is False
    assert finding.raw["candidate"] is True
    assert finding.raw["source"] == "extracted"
    assert finding.raw["file_path"] == "/fake/blob.bin"
    assert finding.severity in ("critical", "high", "medium", "low")


def test_recognized_region_within_expected_range_is_dropped_not_downgraded() -> None:
    """An XZ-claimed region with in-range entropy is dropped, not kept at a lower severity.

    Under the old global-threshold design this scenario produced a
    downgraded-but-present Finding; under the context-aware design a
    format-consistent region is dropped outright (Change 1) -- there is
    no such thing as a downgraded survivor any more.

    Returns:
        None.

    Raises:
        AssertionError: If a Finding is produced for the recognized blob.
    """
    data = _low_high_low_buffer()
    blob_start = 200_000
    samples = entropy.compute_entropy_samples(data)
    known_regions = [
        binwalk_wrapper.BinwalkRegion(
            offset=blob_start,
            size=len(_MAX_ENTROPY_BLOB),
            description="XZ compressed data",
            is_compression=True,
        )
    ]

    findings, summary = firmware_pipeline._analyze_file_entropy(
        samples, data, known_regions, "firmware_pipeline", "raw_binary", None, None
    )

    assert findings == []
    assert summary.dropped_format_consistent >= 1


def test_recognized_ext4_with_entropy_above_range_is_flagged_as_anomaly() -> None:
    """A recognized ext4 region with entropy above its expected range is a format anomaly.

    Returns:
        None.

    Raises:
        AssertionError: If the finding is not labeled with the recognized
            format, or confidence/severity are not computed.
    """
    region = _region(start=0, end=1000, peak_entropy=7.89)
    data = os.urandom(1000)
    overlap = (0, 1_048_576, "ext4", "ext4 filesystem data", 4.0, 7.5)

    finding = firmware_pipeline._build_candidate_finding(
        region, data, "firmware_pipeline", "raw_binary", None, None, overlap
    )

    assert finding.raw["recognized_format"] == "ext4 filesystem data"
    assert finding.raw["expected_entropy_min"] == 4.0
    assert finding.raw["expected_entropy_max"] == 7.5
    assert finding.raw["candidate"] is True
    assert 0.0 <= finding.raw["confidence"] <= 1.0
    assert finding.severity in ("critical", "high", "medium", "low")
    assert "anomaly" in finding.description.lower()


def test_high_entropy_region_with_no_binwalk_match_has_no_recognized_format() -> None:
    """A candidate region with zero overlapping Binwalk regions has recognized_format=None.

    Returns:
        None.

    Raises:
        AssertionError: If a format is spuriously attached to the finding.
    """
    region = _region(start=10_000, end=11_000, peak_entropy=7.65)
    data = os.urandom(1000)

    finding = firmware_pipeline._build_candidate_finding(
        region, data, "firmware_pipeline", "raw_binary", None, None, overlap=None
    )

    assert finding.raw["recognized_format"] is None
    assert finding.raw["expected_entropy_min"] is None
    assert finding.raw["expected_entropy_max"] is None
    assert "no recognized format" in finding.description


def test_extracted_file_recognized_by_binwalk_still_runs_entropy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A file Binwalk recognizes still gets entropy analysis, not a skip (the Core Rule).

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to stub out Binwalk's scan.

    Returns:
        None.

    Raises:
        AssertionError: If entropy analysis is skipped for a recognized
            file with a genuine local anomaly.
    """
    fake_region = binwalk_wrapper.BinwalkRegion(
        offset=200_000,
        size=len(_MAX_ENTROPY_BLOB),
        description="gzip compressed data",
        is_compression=True,
    )
    monkeypatch.setattr(binwalk_wrapper, "scan_file", lambda filepath: [fake_region])

    extracted_root = tmp_path / "extracted"
    recognized_file = extracted_root / "lib" / "payload.gz"
    recognized_file.parent.mkdir(parents=True)
    # In-range blob (dropped) plus a second, unexplained anomaly outside
    # the recognized region -- proves entropy still ran across the whole
    # file rather than being skipped because Binwalk recognized *something*.
    recognized_file.write_bytes(
        _low_high_low_buffer() + b"\x00" * 200_000 + os.urandom(1) * 0 + _MAX_ENTROPY_BLOB
    )

    findings, summary = firmware_pipeline._analyze_extracted_file(recognized_file, extracted_root)

    assert summary.regions_analyzed >= 2  # both blobs were considered
    assert summary.dropped_format_consistent >= 1  # the gzip-recognized one
    assert len(findings) >= 1  # the unexplained one still surfaces
    assert all(finding.module_name == "firmware_pipeline_extracted" for finding in findings)
    assert all(finding.raw["source"] == "extracted" for finding in findings)
    assert all(finding.raw["file_path"] == str(recognized_file) for finding in findings)


def test_extracted_file_local_anomaly_is_tagged_with_extraction_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unrecognized local anomaly in an extracted file is tagged with its source and path.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to stub out Binwalk's scan.

    Returns:
        None.

    Raises:
        AssertionError: If the finding is missing or mistagged.
    """
    monkeypatch.setattr(binwalk_wrapper, "scan_file", lambda filepath: [])

    extracted_root = tmp_path / "extracted"
    suspicious_file = extracted_root / "tmp" / "blob.bin"
    suspicious_file.parent.mkdir(parents=True)
    suspicious_file.write_bytes(_low_high_low_buffer())

    findings, summary = firmware_pipeline._analyze_extracted_file(suspicious_file, extracted_root)

    assert summary.local_anomaly_candidates >= 1
    assert len(findings) >= 1
    assert all(finding.module_name == "firmware_pipeline_extracted" for finding in findings)
    assert all(finding.raw["source"] == "extracted" for finding in findings)
    assert all(finding.raw["file_path"] == str(suspicious_file) for finding in findings)


def test_pipeline_falls_back_gracefully_when_binwalk_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_pipeline() must not crash when Binwalk is unavailable.

    Simulates the "binwalk not installed" state and verifies the pipeline
    still returns raw-binary candidate findings, all tagged with the
    firmware_pipeline module name, rather than raising or silently
    returning nothing.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to simulate Binwalk being
            unavailable and to redirect output paths.

    Returns:
        None.

    Raises:
        AssertionError: If the pipeline raises, or returns no findings,
            or returns findings not attributed to the fallback path.
    """
    monkeypatch.setattr(binwalk_wrapper, "_BINWALK_AVAILABLE", False)
    monkeypatch.setattr(
        binwalk_wrapper, "_BINWALK_IMPORT_ERROR", ImportError("simulated: binwalk not installed")
    )
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")
    monkeypatch.setattr(config, "BINWALK_EXTRACTION_DIR", tmp_path / "extracted")

    firmware_path = tmp_path / "firmware.bin"
    firmware_path.write_bytes(_low_high_low_buffer())

    findings = firmware_pipeline.run_pipeline(str(firmware_path))

    assert len(findings) >= 1
    assert all(finding.module_name == "firmware_pipeline" for finding in findings)
    assert all(finding.raw.get("candidate") is True for finding in findings)
    assert all(finding.raw.get("recognized_format") is None for finding in findings)


def test_run_pipeline_with_summary_returns_matching_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_pipeline_with_summary() returns an EntropySummary consistent with the findings.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to simulate Binwalk being
            unavailable and to redirect output paths.

    Returns:
        None.

    Raises:
        AssertionError: If the summary's candidate count doesn't match
            the number of findings returned, or run_pipeline() (the
            main.py-facing wrapper) disagrees with it.
    """
    monkeypatch.setattr(binwalk_wrapper, "_BINWALK_AVAILABLE", False)
    monkeypatch.setattr(
        binwalk_wrapper, "_BINWALK_IMPORT_ERROR", ImportError("simulated: binwalk not installed")
    )
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")
    monkeypatch.setattr(config, "BINWALK_EXTRACTION_DIR", tmp_path / "extracted")

    firmware_path = tmp_path / "firmware.bin"
    firmware_path.write_bytes(_low_high_low_buffer())

    findings, summary = firmware_pipeline.run_pipeline_with_summary(str(firmware_path))
    findings_via_wrapper = firmware_pipeline.run_pipeline(str(firmware_path))

    assert isinstance(summary, firmware_pipeline.EntropySummary)
    assert summary.local_anomaly_candidates + summary.whole_file_anomalies == len(findings)
    assert len(findings_via_wrapper) == len(findings)


def _mock_extract_with_fake_extracted_dir(monkeypatch: pytest.MonkeyPatch, extracted_dir: Path) -> None:
    """Stub binwalk_wrapper.extract() to report `extracted_dir` as already extracted.

    Args:
        monkeypatch: Pytest fixture used to patch `binwalk_wrapper.extract`.
        extracted_dir: Directory to report as the extraction result.

    Returns:
        None.

    Raises:
        None.
    """
    monkeypatch.setattr(
        binwalk_wrapper,
        "extract",
        lambda filepath, output_dir: binwalk_wrapper.BinwalkResult(
            known_regions=[], extracted_dir=extracted_dir
        ),
    )


def test_extracted_directory_deleted_after_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The extracted directory tree is deleted once run_pipeline() returns.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to stub Binwalk's extraction and
            redirect plot output.

    Returns:
        None.

    Raises:
        AssertionError: If the extracted directory survives cleanup, or
            the original firmware file no longer exists.
    """
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")

    extracted_dir = tmp_path / "_firmware.bin.extracted"
    extracted_dir.mkdir()
    # Below EXTRACTED_MIN_FILE_SIZE, so the walk skips it without needing
    # a real (or mocked) Binwalk scan of its contents -- entropy findings
    # are irrelevant to this test, which only checks cleanup.
    (extracted_dir / "tiny.bin").write_bytes(b"\x00" * 10)
    _mock_extract_with_fake_extracted_dir(monkeypatch, extracted_dir)

    firmware_path = tmp_path / "firmware.bin"
    firmware_path.write_bytes(b"\x00" * 200)  # low entropy -> no findings

    firmware_pipeline.run_pipeline(str(firmware_path))

    assert not extracted_dir.exists()
    assert firmware_path.exists()


def test_original_firmware_untouched_after_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The original firmware file's content is byte-identical after cleanup.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to stub Binwalk's extraction and
            redirect plot output.

    Returns:
        None.

    Raises:
        AssertionError: If the firmware file's SHA-256 hash changes, or
            it no longer exists at its original path.
    """
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")

    extracted_dir = tmp_path / "_firmware.bin.extracted"
    extracted_dir.mkdir()
    (extracted_dir / "tiny.bin").write_bytes(b"\x00" * 10)
    _mock_extract_with_fake_extracted_dir(monkeypatch, extracted_dir)

    firmware_path = tmp_path / "firmware.bin"
    firmware_content = b"\x00" * 200
    firmware_path.write_bytes(firmware_content)
    original_hash = hashlib.sha256(firmware_content).hexdigest()

    firmware_pipeline.run_pipeline(str(firmware_path))

    assert firmware_path.exists()
    assert hashlib.sha256(firmware_path.read_bytes()).hexdigest() == original_hash


def test_filesystem_findings_merge_into_pipeline_and_cleanup_still_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """filesystem.py's checks run automatically on the pipeline's own extraction.

    Reuses the same extraction already on disk (no second extraction) --
    plants a backdoor-account passwd file under the mocked extracted
    directory, confirms a module_name="filesystem" finding merges into
    run_pipeline()'s combined output, and confirms the mandatory cleanup
    still removes the extracted directory afterward even though
    filesystem.py contributed findings.

    Args:
        tmp_path: Pytest-provided temporary directory.
        monkeypatch: Pytest fixture used to stub Binwalk's extraction/scan
            and redirect plot output.

    Returns:
        None.

    Raises:
        AssertionError: If no filesystem finding is produced, or the
            extracted directory survives cleanup.
    """
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")
    # _walk_extracted() also runs against this same directory; stub its
    # own Binwalk scan so this test doesn't depend on a real install.
    monkeypatch.setattr(binwalk_wrapper, "scan_file", lambda filepath: [])

    extracted_dir = tmp_path / "_firmware.bin.extracted"
    (extracted_dir / "etc").mkdir(parents=True)
    (extracted_dir / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\n"
        "backdoor:x:0:0:backdoor:/root:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/:/bin/false\n"
    )
    _mock_extract_with_fake_extracted_dir(monkeypatch, extracted_dir)

    firmware_path = tmp_path / "firmware.bin"
    firmware_path.write_bytes(b"\x00" * 200)

    findings = firmware_pipeline.run_pipeline(str(firmware_path))

    filesystem_findings = [f for f in findings if f.module_name == "filesystem"]
    assert len(filesystem_findings) == 1
    assert filesystem_findings[0].severity == "high"
    assert not extracted_dir.exists()
    assert firmware_path.exists()
