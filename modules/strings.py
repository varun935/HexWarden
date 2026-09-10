"""String extraction and pattern-matching module for HexWarden.

Extracts printable ASCII (minimum `config.STRINGS_MIN_ASCII_LENGTH`
characters) and UTF-16LE strings from a firmware binary via a pure-Python
sliding regex scan -- no shell-out to the `strings` binary -- then scans
each extracted string against a pattern library loaded from
`config.STRING_PATTERNS_PATH` (config/string_patterns.json), so the
patterns themselves can be edited without a code change.

Categories detected: hardcoded IPs, suspicious domains (dynamic-DNS/.onion
style, not every URL -- see false-positive discipline below), shell
commands, credential-looking assignments, base64 blobs (decoded and
re-scanned one level deep), and C2-style hardcoded ports.

False-positive discipline: router firmware legitimately contains IPs
(NTP, DNS), shell references (init scripts), and URLs (update servers);
ESP-IDF/embedded firmware additionally contains large debug-symbol
tables (function names, compiler/toolchain file paths) that happen to
sit inside the base64 charset. A single, isolated match of any pattern
defaults to LOW (or MEDIUM for the more inherently sensitive categories
-- credentials, C2 ports) and is never treated as a verdict on its own;
only *co-occurrence across different categories* -- e.g. a shell_command
AND a hardcoded_ip within `config.STRINGS_CO_OCCURRENCE_WINDOW_BYTES` of
each other -- escalates severity. Multiple matches of the *same*
category clustered together (a whole symbol table of base64-looking
strings, say) do NOT escalate each other -- that was a real bug: a
debug-symbol table could mass-escalate itself to CRITICAL purely by
being long, with no actual heterogeneous suspicion behind it.
`config.NETWORK_MONITOR_KNOWN_CLOUD_RANGES`-style allowlists
(`allowlisted_ips`, `allowlisted_domains` in the pattern file) suppress
the common legitimate offenders outright. base64_blob candidates are
additionally filtered by `_is_valid_base64_candidate()` -- length,
character-density, and shape checks that reject file paths, whitespace-
free identifiers, and camelCase function names before they ever reach
scoring.

Inputs:
    filepath (str): Path to a firmware binary file to analyze.

Outputs:
    List[Finding]: One Finding per suspicious string match (or
    escalated cluster of matches). Empty list if nothing suspicious is
    found.
"""

import argparse
import base64
import binascii
import json
import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import config
from core import AnalysisError, Finding

logger = logging.getLogger(__name__)

MODULE_NAME = "strings"

# Severity rank, mirroring modules/entropy.py's own local `_SEVERITY_RANK`
# -- used to make sure co-occurrence escalation only ever raises a
# match's severity, never lowers it below its category's base severity.
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Per-category base severity for an isolated (non-co-occurring) match.
# Credentials and C2-style ports are inherently more sensitive than an
# incidental IP or shell-command reference, so they start at MEDIUM
# rather than LOW even alone -- everything still needs co-occurrence (or
# an allowlist miss) to climb further.
_BASE_SEVERITY_BY_CATEGORY = {
    "hardcoded_ip": "low",
    "suspicious_domain": "medium",
    "shell_command": "low",
    "credential_pattern": "medium",
    "base64_blob": "low",
    "c2_port": "medium",
}

# Baseline confidence per severity tier (0.0-1.0), nudged slightly by
# category below -- this is a coarse signal, not a probability model.
_BASE_CONFIDENCE_BY_SEVERITY = {"low": 0.30, "medium": 0.50, "high": 0.75, "critical": 0.95}
_CONFIDENCE_CATEGORY_ADJUSTMENT = {
    "credential_pattern": 0.05,
    "c2_port": 0.05,
    "hardcoded_ip": -0.05,  # routers legitimately reference many IPs
}

_MATCHED_STRING_PREVIEW_LENGTH = 100
_BASE64_MAX_DECODE_LENGTH = 4096  # cap decode/re-scan cost on pathological runs

# base64_blob false-positive-discipline thresholds (see
# `_is_valid_base64_candidate()`). Local to this module rather than
# config.py -- these are shape/plausibility heuristics for one detection
# category, not a tunable a user would reasonably want to retune per
# firmware target.
_BASE64_MIN_LENGTH = 40  # below this, "looks like base64" is too common to be useful
_BASE64_MAX_CAMELCASE_TRANSITIONS = 2  # function names (xQueueReceiveFromISR) have many
_BASE64_MIN_SYMBOL_DENSITY = 0.30  # fraction that must be digits or + / =
_CAMELCASE_TRANSITION_RE = re.compile(r"[a-z][A-Z]")

_ASCII_STRING_RE = re.compile(
    rb"[\x20-\x7e]{" + str(config.STRINGS_MIN_ASCII_LENGTH).encode() + rb",}"
)
_UTF16LE_STRING_RE = re.compile(
    rb"(?:[\x20-\x7e]\x00){" + str(config.STRINGS_MIN_ASCII_LENGTH).encode() + rb",}"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\b"
)
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_BASE64_MIN_LENGTH) + r",}={0,2}")
_C2_PORT_RE = re.compile(r":(\d{4,5})\b")


def _is_valid_base64_candidate(blob: str) -> bool:
    """Apply false-positive-discipline checks to a base64-charset match.

    The bare `_BASE64_BLOB_RE` character class already can't match
    whitespace, `.`, or `\\` (they're not in `[A-Za-z0-9+/]`), so those
    checks below are currently unreachable in practice -- kept anyway as
    explicit, self-documenting guards rather than relying on that being
    true forever. `/` and a leading `@` ARE reachable today (`/` is a
    legal base64 character; ESP-IDF/embedded firmware's compiler/toolchain
    file paths like "components/esp32/include/esp_wifi.h" are pure
    `[A-Za-z0-9+/]` and were the actual source of the false-positive flood
    this function exists to fix), so those two checks carry real weight.

    Args:
        blob: The raw regex match text (before any length truncation).

    Returns:
        True if `blob` plausibly looks like encoded data rather than an
        identifier, file path, or natural-language word run.

    Raises:
        None.
    """
    if len(blob) < _BASE64_MIN_LENGTH:
        return False
    if any(separator in blob for separator in ("/", "\\", ".")):
        return False
    if any(character.isspace() for character in blob):
        return False
    if "_" in blob:
        return False
    if len(_CAMELCASE_TRANSITION_RE.findall(blob)) > _BASE64_MAX_CAMELCASE_TRANSITIONS:
        return False
    symbol_count = sum(1 for character in blob if character.isdigit() or character in "+/=")
    if symbol_count / len(blob) < _BASE64_MIN_SYMBOL_DENSITY:
        return False
    if blob.startswith("/") or blob.startswith("@"):
        return False
    return True


@dataclass
class _RawMatch:
    """One suspicious-string match before severity/clustering is applied.

    Attributes:
        offset: Byte offset in the firmware where the matched string
            begins.
        category: Pattern category (see `_BASE_SEVERITY_BY_CATEGORY`).
        matched_pattern: The specific pattern/keyword that matched.
        matched_string: The extracted string the match was found in
            (may be longer than the matched substring itself).
        base64_decoded: Decoded preview, if this match is a base64 blob
            that successfully decoded to something re-scannable.
    """

    offset: int
    category: str
    matched_pattern: str
    matched_string: str
    base64_decoded: Optional[str] = None


def _load_patterns(patterns_path: Path) -> dict:
    """Load the pattern library from `config.STRING_PATTERNS_PATH`.

    Args:
        patterns_path: Path to the pattern library JSON file.

    Returns:
        Parsed pattern library dict (see config/string_patterns.json).

    Raises:
        AnalysisError: If the file is missing or not valid JSON.
    """
    try:
        return json.loads(patterns_path.read_text())
    except OSError as exc:
        raise AnalysisError(f"Failed to read pattern library {patterns_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AnalysisError(f"Pattern library {patterns_path} is not valid JSON: {exc}") from exc


def _extract_strings(data: bytes) -> List[tuple]:
    """Extract printable ASCII and UTF-16LE strings via a sliding regex scan.

    Args:
        data: Raw firmware bytes.

    Returns:
        List of (offset, text) tuples, one per extracted string, in
        offset order. ASCII and UTF-16LE runs cannot overlap each other
        (UTF-16LE's interleaved null bytes break any ASCII run before it
        reaches the minimum length), so no deduplication is needed.

    Raises:
        None.
    """
    strings = [
        (match.start(), match.group().decode("ascii"))
        for match in _ASCII_STRING_RE.finditer(data)
    ]
    strings.extend(
        (match.start(), match.group().decode("utf-16le"))
        for match in _UTF16LE_STRING_RE.finditer(data)
    )
    strings.sort(key=lambda item: item[0])
    return strings


def _domain_is_allowlisted(domain: str, allowlisted_domains: List[str]) -> bool:
    """Check whether a domain matches (or is a subdomain of) an allowlisted domain.

    Args:
        domain: Candidate domain string.
        allowlisted_domains: Domains from the pattern library's
            `allowlisted_domains` list.

    Returns:
        True if `domain` equals or ends with `.`-prefixed any allowlisted
        domain (e.g. "downloads.openwrt.org" is allowlisted by
        "openwrt.org").

    Raises:
        None.
    """
    domain_lower = domain.lower()
    return any(
        domain_lower == allowed or domain_lower.endswith("." + allowed)
        for allowed in allowlisted_domains
    )


def _scan_text(
    offset: int, text: str, patterns: dict, allow_nested_base64: bool = True
) -> List[_RawMatch]:
    """Scan one extracted string against every pattern category.

    Args:
        offset: File offset where `text` begins.
        text: The extracted string (ASCII or decoded UTF-16LE).
        patterns: Pattern library loaded by `_load_patterns()`.
        allow_nested_base64: Whether to decode and recursively re-scan
            base64 blobs found in `text`. Capped to one level (the
            recursive call passes False) so a base64 blob whose decoded
            content happens to itself look like base64 doesn't recurse
            indefinitely.

    Returns:
        Zero or more `_RawMatch` records, one per pattern hit -- for a
        base64 blob that decodes successfully, this includes both the
        blob match itself and any suspicious patterns found in its
        decoded content (each tagged with `base64_decoded` set).

    Raises:
        None.
    """
    matches: List[_RawMatch] = []
    preview = text[:_MATCHED_STRING_PREVIEW_LENGTH]

    for ip_match in _IPV4_RE.finditer(text):
        ip = ip_match.group()
        if ip in patterns.get("allowlisted_ips", []):
            continue
        matches.append(
            _RawMatch(offset + ip_match.start(), "hardcoded_ip", ip, preview)
        )

    for domain_match in _DOMAIN_RE.finditer(text):
        domain = domain_match.group()
        is_suspicious = any(
            marker in domain.lower() for marker in patterns.get("suspicious_domains", [])
        )
        if not is_suspicious:
            continue  # legitimate-looking domains are not flagged just for existing
        if _domain_is_allowlisted(domain, patterns.get("allowlisted_domains", [])):
            continue
        matches.append(
            _RawMatch(offset + domain_match.start(), "suspicious_domain", domain, preview)
        )

    text_lower = text.lower()
    for shell_cmd in patterns.get("shell_commands", []):
        position = text_lower.find(shell_cmd.lower())
        if position != -1:
            matches.append(
                _RawMatch(offset + position, "shell_command", shell_cmd, preview)
            )

    for credential_pattern in patterns.get("credential_patterns", []):
        position = text_lower.find(credential_pattern.lower())
        if position != -1:
            matches.append(
                _RawMatch(offset + position, "credential_pattern", credential_pattern, preview)
            )

    c2_ports = set(patterns.get("c2_ports", []))
    for port_match in _C2_PORT_RE.finditer(text):
        port = int(port_match.group(1))
        if port in c2_ports:
            matches.append(
                _RawMatch(offset + port_match.start(), "c2_port", f":{port}", preview)
            )

    for base64_match in _BASE64_BLOB_RE.finditer(text):
        blob = base64_match.group()
        if not _is_valid_base64_candidate(blob):
            continue
        blob_offset = offset + base64_match.start()
        decoded_bytes = _decode_base64_blob(blob) if allow_nested_base64 else None
        decoded_preview = (
            decoded_bytes[:_MATCHED_STRING_PREVIEW_LENGTH].decode("ascii", errors="replace")
            if decoded_bytes
            else None
        )
        matches.append(
            _RawMatch(blob_offset, "base64_blob", blob[:40], preview, base64_decoded=decoded_preview)
        )

        if decoded_bytes:
            for _rel_offset, decoded_text in _extract_strings(decoded_bytes):
                nested_matches = _scan_text(
                    blob_offset, decoded_text, patterns, allow_nested_base64=False
                )
                for nested in nested_matches:
                    nested.base64_decoded = decoded_preview
                matches.extend(nested_matches)

    return matches


def _decode_base64_blob(blob: str) -> Optional[bytes]:
    """Attempt to base64-decode a candidate blob.

    Args:
        blob: Candidate base64-charset string.

    Returns:
        Decoded bytes if decoding succeeds, else None. Input is capped
        at `_BASE64_MAX_DECODE_LENGTH` to bound decode/re-scan cost on
        pathologically long runs.

    Raises:
        None.
    """
    if len(blob) > _BASE64_MAX_DECODE_LENGTH:
        blob = blob[:_BASE64_MAX_DECODE_LENGTH]
    padded = blob + "=" * (-len(blob) % 4)
    try:
        return base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return None


def _cluster_category_counts(matches: List[_RawMatch]) -> List[int]:
    """Compute, for each match, the count of DISTINCT categories within the co-occurrence window.

    Escalation is driven by category diversity, not raw match volume: a
    debug-symbol table full of same-category base64_blob matches sitting
    next to each other must not mass-escalate itself to CRITICAL just by
    being long. Two matches of the same category 500 bytes apart is
    normal, uninteresting clustering (a symbol table, a run of similar
    strings); a shell_command sitting next to a hardcoded_ip is a real
    heterogeneous signal.

    Args:
        matches: Matches sorted by `offset` ascending (caller's
            responsibility -- `analyze()` already sorts before calling
            this).

    Returns:
        List parallel to `matches`: for each index, the number of
        distinct `category` values (including its own) among matches
        within `config.STRINGS_CO_OCCURRENCE_WINDOW_BYTES` bytes.

    Raises:
        None.
    """
    window = config.STRINGS_CO_OCCURRENCE_WINDOW_BYTES
    counts = [0] * len(matches)
    left = 0
    right = 0
    n = len(matches)
    for i, match in enumerate(matches):
        current = match.offset
        while left < n and matches[left].offset < current - window:
            left += 1
        if right < i:
            right = i
        while right < n and matches[right].offset <= current + window:
            right += 1
        counts[i] = len({m.category for m in matches[left:right]})
    return counts


def _severity_for_match(category: str, category_count: int) -> str:
    """Determine a match's final severity from its category and co-occurring category diversity.

    Args:
        category: Pattern category.
        category_count: Number of DISTINCT suspicious-string categories
            (including this match's own) within the co-occurrence window
            (see `_cluster_category_counts()`).

    Returns:
        "low", "medium", "high", or "critical" -- co-occurrence only ever
        raises the category's base severity, never lowers it. Two
        distinct co-occurring categories = HIGH, three or more =
        CRITICAL. Any number of matches of the SAME category clustered
        together leaves `category_count` at 1 and does not escalate.

    Raises:
        None.
    """
    base_severity = _BASE_SEVERITY_BY_CATEGORY.get(category, "low")
    if category_count >= 3:
        cluster_severity = "critical"
    elif category_count == 2:
        cluster_severity = "high"
    else:
        cluster_severity = base_severity

    if _SEVERITY_RANK[cluster_severity] > _SEVERITY_RANK[base_severity]:
        return cluster_severity
    return base_severity


def _confidence_for_match(category: str, severity: str) -> float:
    """Compute a 0.0-1.0 confidence score for a match.

    Args:
        category: Pattern category.
        severity: Final severity from `_severity_for_match()`.

    Returns:
        Confidence clamped to [0.0, 1.0].

    Raises:
        None.
    """
    confidence = _BASE_CONFIDENCE_BY_SEVERITY[severity]
    confidence += _CONFIDENCE_CATEGORY_ADJUSTMENT.get(category, 0.0)
    return max(0.0, min(1.0, confidence))


def _describe(category: str, matched_pattern: str, category_count: int) -> str:
    """Build a human-readable description for a match.

    Args:
        category: Pattern category.
        matched_pattern: The specific pattern/keyword that matched.
        category_count: Number of distinct suspicious-string categories
            within the co-occurrence window (see
            `_cluster_category_counts()`).

    Returns:
        A one-sentence description, noting cross-category co-occurrence
        when it drove the severity.

    Raises:
        None.
    """
    label = category.replace("_", " ")
    description = f"Suspicious {label} string matched {matched_pattern!r}"
    if category_count >= 2:
        other = category_count - 1
        noun = "category" if other == 1 else "categories"
        description += f" (co-occurring with {other} other suspicious {noun} nearby)"
    return description


def analyze(filepath: str) -> List[Finding]:
    """Extract and pattern-match strings in a firmware binary.

    Args:
        filepath: Absolute or relative path to firmware binary.

    Returns:
        List of Finding objects, one per suspicious string match. Empty
        list if nothing suspicious is found.

    Raises:
        FileNotFoundError: If the firmware file does not exist.
        AnalysisError: If the file cannot be read or the pattern
            library cannot be loaded.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {filepath}")

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise AnalysisError(f"Failed to read firmware file {filepath}: {exc}") from exc

    patterns = _load_patterns(config.STRING_PATTERNS_PATH)

    logger.info("Extracting strings from %s (%d bytes)", path, len(data))
    strings = _extract_strings(data)
    logger.info("Extracted %d string(s); scanning for suspicious patterns", len(strings))

    raw_matches: List[_RawMatch] = []
    for offset, text in strings:
        raw_matches.extend(_scan_text(offset, text, patterns))

    if not raw_matches:
        logger.info("String analysis complete: 0 finding(s)")
        return []

    raw_matches.sort(key=lambda match: match.offset)
    category_counts = _cluster_category_counts(raw_matches)

    findings: List[Finding] = []
    for match, category_count in zip(raw_matches, category_counts):
        severity = _severity_for_match(match.category, category_count)
        confidence = _confidence_for_match(match.category, severity)
        raw: Dict = {
            "matched_pattern": match.matched_pattern,
            "matched_string": match.matched_string[:_MATCHED_STRING_PREVIEW_LENGTH],
            "category": match.category,
            "offset": match.offset,
            # Distinct co-occurring categories within the window (see
            # `_cluster_category_counts()`), NOT a raw match count --
            # kept under this key name for backward compatibility with
            # existing readers (e.g. the web dashboard).
            "co_occurring_count": category_count,
            "confidence": confidence,
        }
        if match.base64_decoded is not None:
            raw["base64_decoded"] = match.base64_decoded

        findings.append(
            Finding(
                module_name=MODULE_NAME,
                severity=severity,
                offset=match.offset,
                description=_describe(match.category, match.matched_pattern, category_count),
                evidence=match.matched_string[:_MATCHED_STRING_PREVIEW_LENGTH],
                score=config.SEVERITY_SCORE_WEIGHTS[severity],
                raw=raw,
            )
        )

    logger.info("String analysis complete: %d finding(s)", len(findings))
    return findings


def _write_report(firmware_path: Path, findings: List[Finding], output_dir: Path) -> Path:
    """Write findings to a timestamped JSON report, matching main.py's format.

    Args:
        firmware_path: The firmware file that was analyzed.
        findings: Findings returned by `analyze()`.
        output_dir: Directory to write the report into (created if
            missing).

    Returns:
        Path to the written report file.

    Raises:
        None.
    """
    from dataclasses import asdict

    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"report_{MODULE_NAME}_{firmware_path.stem}_{timestamp}.json"
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump([asdict(finding) for finding in findings], report_file, indent=2)
    return report_path


def _main() -> None:
    """Command-line entry point for standalone module execution.

    Args:
        None. Arguments are read from sys.argv via argparse.

    Returns:
        None.

    Raises:
        SystemExit: If the firmware file argument is missing/invalid, or
            if analysis fails.
    """
    parser = argparse.ArgumentParser(
        description="Extract and pattern-match strings in a firmware image."
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
        logger.error("String analysis failed: %s", exc)
        sys.exit(1)

    if not findings:
        print("No suspicious strings detected.")
    else:
        print(f"Detected {len(findings)} suspicious string(s):")
        for finding in findings:
            print(
                f"  [{finding.severity.upper()}] offset={finding.offset} "
                f"category={finding.raw['category']} score={finding.score} - "
                f"{finding.description}"
            )

    report_path = _write_report(Path(args.firmware), findings, config.DEFAULT_OUTPUT_DIR)
    print(f"\nFull report written to: {report_path}")


if __name__ == "__main__":
    _main()
