"""Filesystem anomaly scanner for HexWarden.

Walks an already-extracted firmware filesystem (typically the output of
`binwalk_wrapper.extract()`) looking for five specific, high-precision
anomaly patterns rather than attempting to catalog every possible
persistence mechanism:

    1. A second UID-0 account in any `passwd` file -- a real Linux system
       has exactly one (`root`); a second is a backdoor account.
    2. Cron/init persistence entries referencing a non-standard path, a
       hardcoded IP, or a base64-looking string.
    3. Pre-installed SSH `authorized_keys` files (flagged for review
       either way -- could be legitimate vendor support access or not).
    4. Executable files sitting in runtime-only locations (`/tmp/`,
       `/var/tmp/`, `/dev/shm/`, or any hidden path) that should not ship
       persistent executables in a firmware image.
    5. World-writable files under system directories (`/etc/`, `/bin/`,
       `/sbin/`, `/usr/bin/`, `/usr/sbin/`) -- a privilege-escalation
       vector if anything can rewrite a system binary or config.

This module runs standalone and returns its own findings; it does not
cross-reference entropy or YARA results -- corroboration across modules
happens in the scoring engine, not here.

Inputs:
    extracted_dir (str): Path to the root of an extracted firmware
        filesystem.

Outputs:
    List[Finding]: One Finding per detected anomaly. `offset` is always
    None (these are filesystem checks, not byte-offset-based); the
    affected file is identified via `raw["file_path"]` instead.
"""

import base64
import binascii
import hashlib
import logging
import re
import stat
from pathlib import Path
from typing import List, Optional

import config
from core import AnalysisError, Finding

logger = logging.getLogger(__name__)

MODULE_NAME = "filesystem"

# Path prefixes a cron/init entry is expected to reference on a normal
# system (Check 2). Anything else referenced by an absolute path is
# treated as suspicious.
_STANDARD_CRON_PATH_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/etc/")

_IP_ADDRESS_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ABSOLUTE_PATH_RE = re.compile(r"/[\w.-]+(?:/[\w.-]+)+")
_BASE64_RE = re.compile(
    r"[A-Za-z0-9+/]{" + str(config.FILESYSTEM_BASE64_MIN_LENGTH) + r",}={0,2}"
)


def _relative_location(filepath: Path, extracted_dir: Path) -> str:
    """Render a file's path relative to the extraction root, POSIX-style with a leading slash.

    Args:
        filepath: Path to a file under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        A string like "/etc/passwd" suitable for prefix/substring
        matching against `config.py`'s location lists.

    Raises:
        None.
    """
    try:
        relative = filepath.relative_to(extracted_dir)
    except ValueError:
        relative = filepath
    return "/" + relative.as_posix()


def _finding(severity: str, description: str, evidence: str, file_path: Path, location: str) -> Finding:
    """Build a Finding with this module's common fields filled in.

    Args:
        severity: "low", "medium", "high", or "critical".
        description: Human-readable explanation of the anomaly.
        evidence: The specific value that triggered the finding.
        file_path: Path to the affected file.
        location: Result of `_relative_location()` for that file.

    Returns:
        A Finding with `module_name`, `offset=None`, `score`, and a raw
        dict carrying `file_path`.

    Raises:
        None.
    """
    return Finding(
        module_name=MODULE_NAME,
        severity=severity,
        offset=None,
        description=description,
        evidence=evidence,
        score=config.SEVERITY_SCORE_WEIGHTS[severity],
        raw={"file_path": str(file_path), "location": location},
    )


def _check_root_accounts(files: List[Path], extracted_dir: Path) -> List[Finding]:
    """Check 1: flag any UID-0 passwd entry that is not the legitimate `root` account.

    Args:
        files: All files under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        One HIGH finding per anomalous UID-0 entry found in any `passwd`
        file.

    Raises:
        None.
    """
    findings: List[Finding] = []
    for filepath in files:
        if filepath.name != "passwd":
            continue
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
        except OSError:
            logger.warning("Could not read %s; skipping root-account check", filepath)
            continue

        location = _relative_location(filepath, extracted_dir)
        for line in lines:
            fields = line.split(":")
            if len(fields) < 3:
                continue
            username, uid = fields[0], fields[2]
            if uid == "0" and username != "root":
                findings.append(
                    _finding(
                        "high",
                        f"Unexpected UID-0 account {location!r}: {username!r} has root "
                        "privileges but is not the legitimate 'root' account",
                        evidence=line.strip(),
                        file_path=filepath,
                        location=location,
                    )
                )
    return findings


def _cron_file_matches(location: str) -> bool:
    """Check whether a file's location matches one of `config.FILESYSTEM_CRON_PATHS`.

    Args:
        location: Result of `_relative_location()` for the file.

    Returns:
        True if any configured cron path appears in `location`.

    Raises:
        None.
    """
    return any(f"/{cron_path}" in location for cron_path in config.FILESYSTEM_CRON_PATHS)


def _describe_cron_anomaly(content: str) -> Optional[str]:
    """Determine why a cron file's content is suspicious, if it is.

    Args:
        content: Full text content of the cron file.

    Returns:
        A short description of the first suspicious pattern found
        (non-standard path, hardcoded IP, or base64-looking string), or
        None if nothing suspicious is present.

    Raises:
        None.
    """
    for path_match in _ABSOLUTE_PATH_RE.findall(content):
        if not path_match.startswith(_STANDARD_CRON_PATH_PREFIXES):
            return f"references a non-standard path ({path_match})"
    ip_match = _IP_ADDRESS_RE.search(content)
    if ip_match:
        return f"references a hardcoded IP address ({ip_match.group()})"
    base64_match = _BASE64_RE.search(content)
    if base64_match:
        return "contains a base64-looking string"
    return None


def _check_cron_persistence(files: List[Path], extracted_dir: Path) -> List[Finding]:
    """Check 2: flag cron/init files referencing non-standard paths, IPs, or base64 blobs.

    Standard router cron content (logrotate, ntp sync, etc.) referencing
    only `/usr/`, `/bin/`, `/sbin/`, or `/etc/` paths is left alone --
    only entries matching a specific suspicious pattern are flagged.

    Args:
        files: All files under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        One MEDIUM finding per cron file whose content matches a
        suspicious pattern.

    Raises:
        None.
    """
    findings: List[Finding] = []
    for filepath in files:
        location = _relative_location(filepath, extracted_dir)
        if not _cron_file_matches(location):
            continue
        try:
            content = filepath.read_text(errors="ignore")
        except OSError:
            logger.warning("Could not read %s; skipping cron check", filepath)
            continue

        reason = _describe_cron_anomaly(content)
        if reason is not None:
            findings.append(
                _finding(
                    "medium",
                    f"Suspicious cron/persistence entry {location!r}: {reason}",
                    evidence=reason,
                    file_path=filepath,
                    location=location,
                )
            )
    return findings


def _fingerprint_key_line(line: str) -> Optional[str]:
    """Compute a SHA-256 fingerprint for one authorized_keys line.

    Args:
        line: One line from an authorized_keys file.

    Returns:
        A "SHA256:<hex>" fingerprint of the decoded key material (falling
        back to fingerprinting the raw line text if it doesn't parse as a
        standard "<type> <base64-key> [comment]" line), or None for a
        blank/comment line.

    Raises:
        None.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None

    parts = stripped.split()
    if len(parts) >= 2:
        try:
            key_bytes = base64.b64decode(parts[1], validate=True)
            return f"SHA256:{hashlib.sha256(key_bytes).hexdigest()}"
        except (ValueError, binascii.Error):
            pass
    return f"SHA256:{hashlib.sha256(stripped.encode()).hexdigest()}"


def _check_authorized_keys(files: List[Path], extracted_dir: Path) -> List[Finding]:
    """Check 3: flag any pre-installed SSH authorized_keys file.

    Args:
        files: All files under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        One MEDIUM (informational) finding per authorized_keys file
        found, with each key's fingerprint in the evidence field for
        cross-referencing across firmware samples.

    Raises:
        None.
    """
    findings: List[Finding] = []
    for filepath in files:
        if filepath.name != "authorized_keys" or ".ssh" not in filepath.parts:
            continue
        try:
            lines = filepath.read_text(errors="ignore").splitlines()
        except OSError:
            logger.warning("Could not read %s; skipping authorized_keys check", filepath)
            continue

        fingerprints = [
            fingerprint
            for fingerprint in (_fingerprint_key_line(line) for line in lines)
            if fingerprint is not None
        ]
        if not fingerprints:
            continue

        location = _relative_location(filepath, extracted_dir)
        findings.append(
            _finding(
                "medium",
                f"Pre-installed SSH authorized_keys file {location!r} "
                f"({len(fingerprints)} key(s)) -- confirm this is intentional "
                "vendor support access, not a backdoor",
                evidence="; ".join(fingerprints),
                file_path=filepath,
                location=location,
            )
        )
    return findings


def _is_hidden_path(location: str) -> bool:
    """Check whether any path component of a location is a hidden dotfile/dotdir.

    Args:
        location: Result of `_relative_location()` for the file.

    Returns:
        True if any path component starts with "." (excluding "." and
        "..").

    Raises:
        None.
    """
    return any(
        part.startswith(".") and part not in (".", "..") for part in Path(location).parts
    )


def _check_suspicious_executables(files: List[Path], extracted_dir: Path) -> List[Finding]:
    """Check 4: flag executable files in runtime-only or hidden locations.

    Args:
        files: All files under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        One HIGH finding per executable file found under
        `config.FILESYSTEM_SUSPICIOUS_EXEC_LOCATIONS` or any hidden path
        -- a classic persistence/dropper pattern, since these are
        runtime-only directories that should not ship persistent
        executables in a firmware image.

    Raises:
        None.
    """
    findings: List[Finding] = []
    for filepath in files:
        try:
            mode = filepath.stat().st_mode
        except OSError:
            continue
        if not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            continue

        location = _relative_location(filepath, extracted_dir)
        in_suspicious_location = any(
            marker in location for marker in config.FILESYSTEM_SUSPICIOUS_EXEC_LOCATIONS
        )
        if in_suspicious_location or _is_hidden_path(location):
            findings.append(
                _finding(
                    "high",
                    f"Executable file in a runtime-only or hidden location {location!r} "
                    "-- persistent executables should not ship here",
                    evidence=f"mode={oct(stat.S_IMODE(mode))}",
                    file_path=filepath,
                    location=location,
                )
            )
    return findings


def _check_world_writable(files: List[Path], extracted_dir: Path) -> List[Finding]:
    """Check 5: flag world-writable files under system directories.

    Args:
        files: All files under `extracted_dir`.
        extracted_dir: Root directory the filesystem was extracted under.

    Returns:
        One MEDIUM finding per world-writable file under
        `config.FILESYSTEM_SYSTEM_DIRS_CHECK_WRITABLE` -- a
        privilege-escalation vector, since anything that can rewrite a
        system binary or config file has a route to persistence.

    Raises:
        None.
    """
    findings: List[Finding] = []
    for filepath in files:
        try:
            mode = filepath.stat().st_mode
        except OSError:
            continue
        if not mode & stat.S_IWOTH:
            continue

        # A substring check, not a strict prefix check: a real extracted
        # firmware filesystem is always nested under at least one
        # intermediate Binwalk-generated directory (e.g.
        # "_firmware.extracted/squashfs-root/etc/passwd"), so "/etc/"
        # rarely appears as a literal path *prefix* -- matches the same
        # convention firmware_pipeline.py uses for its own location lists.
        location = _relative_location(filepath, extracted_dir)
        if any(marker in location for marker in config.FILESYSTEM_SYSTEM_DIRS_CHECK_WRITABLE):
            findings.append(
                _finding(
                    "medium",
                    f"World-writable file in a system directory {location!r} -- a "
                    "privilege-escalation / persistence-injection vector",
                    evidence=f"mode={oct(stat.S_IMODE(mode))}",
                    file_path=filepath,
                    location=location,
                )
            )
    return findings


def analyze(extracted_dir: str) -> List[Finding]:
    """Walk an extracted firmware filesystem and flag anomalies.

    Args:
        extracted_dir: Path to the root of an extracted firmware
            filesystem (typically produced by `binwalk_wrapper.extract()`).

    Returns:
        List of Finding objects, one per detected anomaly, combining all
        five checks (see the module docstring). Empty list if nothing is
        found.

    Raises:
        FileNotFoundError: If `extracted_dir` does not exist or is not a
            directory.
        AnalysisError: If the directory cannot be walked.
    """
    root = Path(extracted_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"Extracted filesystem directory not found: {extracted_dir}")

    try:
        files = [entry for entry in root.rglob("*") if entry.is_file()]
    except OSError as exc:
        raise AnalysisError(f"Failed to walk extracted directory {extracted_dir}: {exc}") from exc

    logger.info("Walking %s (%d files)", root, len(files))

    findings: List[Finding] = []
    findings.extend(_check_root_accounts(files, root))
    findings.extend(_check_cron_persistence(files, root))
    findings.extend(_check_authorized_keys(files, root))
    findings.extend(_check_suspicious_executables(files, root))
    findings.extend(_check_world_writable(files, root))

    logger.info("Filesystem scan complete: %d finding(s)", len(findings))
    return findings


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Walk an extracted firmware filesystem and flag anomalies."
    )
    parser.add_argument("extracted_dir", help="Path to the root of an extracted firmware filesystem")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )

    try:
        results = analyze(args.extracted_dir)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except AnalysisError as exc:
        logger.error("Filesystem scan failed: %s", exc)
        sys.exit(1)

    if not results:
        print("No filesystem anomalies detected.")
    else:
        print(f"Detected {len(results)} anomaly(ies):")
        for result in results:
            print(
                f"  [{result.severity.upper()}] {result.raw['location']} "
                f"score={result.score} - {result.description}"
            )
