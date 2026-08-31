"""Unit tests for modules/entropy.py.

Exercises Shannon entropy computation and sliding-window region detection
against synthetic firmware-like byte buffers, covering uniform low-entropy
data (no findings), an embedded high-entropy payload (finding expected),
and degenerate empty/1-byte/missing input.

Inputs:
    None directly (pytest fixtures create temporary firmware files on disk).

Outputs:
    None (test assertions; pytest reports pass/fail).
"""

import os
from pathlib import Path

import pytest

import config
from modules import entropy


@pytest.fixture(autouse=True)
def _redirect_output_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect entropy plot output to a temporary directory for each test.

    Args:
        tmp_path: Pytest-provided temporary directory, unique per test.
        monkeypatch: Pytest fixture used to patch module attributes.

    Returns:
        None.

    Raises:
        None.
    """
    monkeypatch.setattr(config, "DEFAULT_OUTPUT_DIR", tmp_path / "output")


def test_clean_firmware_has_no_findings(tmp_path: Path) -> None:
    """Uniform low-entropy data should not trigger any findings.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If any finding is unexpectedly produced.
    """
    firmware_path = tmp_path / "clean_firmware.bin"
    firmware_path.write_bytes(b"\x00\x01\x02\x03" * 4096)

    findings = entropy.analyze(str(firmware_path))

    assert findings == []


def test_high_entropy_region_is_detected(tmp_path: Path) -> None:
    """An embedded block of random bytes should produce at least one finding.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no finding is produced or a finding has an
            invalid severity.
    """
    low_entropy_padding = b"\xAA" * 4096
    high_entropy_block = os.urandom(4096)
    firmware_bytes = low_entropy_padding + high_entropy_block + low_entropy_padding

    firmware_path = tmp_path / "trojan_firmware.bin"
    firmware_path.write_bytes(firmware_bytes)

    findings = entropy.analyze(str(firmware_path))

    assert len(findings) >= 1
    assert all(finding.severity in {"low", "medium", "high", "critical"} for finding in findings)
    assert all(finding.module_name == "entropy" for finding in findings)


def test_empty_file_returns_no_findings(tmp_path: Path) -> None:
    """An empty firmware file should return no findings, not raise.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If a finding is produced or an exception occurs.
    """
    firmware_path = tmp_path / "empty.bin"
    firmware_path.write_bytes(b"")

    findings = entropy.analyze(str(firmware_path))

    assert findings == []


def test_one_byte_file_returns_no_findings(tmp_path: Path) -> None:
    """A single-byte firmware file has zero entropy and no findings.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If a finding is produced or an exception occurs.
    """
    firmware_path = tmp_path / "one_byte.bin"
    firmware_path.write_bytes(b"\x42")

    findings = entropy.analyze(str(firmware_path))

    assert findings == []


def test_missing_file_raises_file_not_found_error(tmp_path: Path) -> None:
    """Analyzing a nonexistent path should raise FileNotFoundError.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If FileNotFoundError is not raised.
    """
    missing_path = tmp_path / "does_not_exist.bin"

    with pytest.raises(FileNotFoundError):
        entropy.analyze(str(missing_path))
