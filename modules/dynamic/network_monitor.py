"""Network traffic monitoring module for HexWarden.

Analyzes a pcap capture -- from real hardware or a synthetically generated
file -- for signs of a firmware trojan phoning home. Four independent
detection features feed one confidence score per connection:

    1. Destination reputation: private/local traffic is skipped outright;
       public destinations on a non-benign port carry full suspicion,
       benign ports (53/80/123) reduce it without skipping inspection,
       and known cloud-provider ranges reduce it further (see the
       documented limitation below).
    2. Payload content inspection: genuinely TLS-encrypted connections
       (detected via a real TLS record layer or the handshake
       ContentType byte, not just port 443) skip payload inspection in
       favor of SNI extraction; everything else is scanned for
       suspicious strings and checked for anomalously high entropy on a
       supposedly-plaintext connection.
    3. DNS anomaly detection: long/high-entropy subdomains or repeated
       queries to the same domain are classic DNS-tunneling indicators.
    4. Beacon timing: connections repeated on a mean interval with low
       variance are a strong C2 signal -- irregular repeats are not.

No single signal here is a verdict; see `_analyze_connection()` for the
additive scoring that combines them into one Finding per suspicious
connection (or per anomalous DNS domain), sorted by confidence descending.

Note: `modules/strings.py` is not yet implemented, so this module defines
its own suspicious-string pattern categories locally (shell commands,
credential-looking assignments, embedded IPs, base64-looking blobs) rather
than importing shared ones. Migrate to a shared source once strings.py
lands.

Documented limitations (do not attempt to work around these):
    - TLS-encrypted payloads are unreadable by design. Payload string/
      entropy inspection is skipped on genuinely encrypted traffic; SNI
      extraction runs instead, since the hostname is visible in the
      ClientHello before encryption begins.
    - CDN/cloud-routed C2 (AWS, Cloudflare, ...) cannot be reliably
      distinguished from legitimate cloud traffic at this level.
      Destination checks reduce confidence for known cloud ranges but
      never skip inspection outright.

Inputs:
    pcap_path (str): Path to a .pcap or .pcapng capture file.

Outputs:
    List[Finding]: One Finding per suspicious connection or anomalous DNS
    domain, sorted by confidence score descending. Empty list if nothing
    is found.
"""

import argparse
import ipaddress
import json
import logging
import re
import statistics
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from scapy.all import DNS, DNSQR, IP, TCP, UDP, PcapReader, Raw, defrag, rdpcap
from scapy.layers.tls.all import TLS, TLSClientHello

import config
from core import AnalysisError, Finding
from modules.entropy import shannon_entropy

logger = logging.getLogger(__name__)

MODULE_NAME = "network_monitor"

# --------------------------------------------------------------------------
# Suspicious payload string patterns, grouped by category (see module
# docstring for why these live here instead of in modules/strings.py).
# --------------------------------------------------------------------------
_SUSPICIOUS_STRING_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # "backdoor" intentionally has no word boundary: real payloads embed
    # it in compound identifiers (e.g. "backdoor_access_key") at least as
    # often as as a standalone word, and it's specific enough that a
    # substring match doesn't meaningfully raise the false-positive rate.
    (re.compile(rb"/bin/(?:sh|bash)|\bwget\b|\bcurl\b|\bnetcat\b|\bnc\b|\bchmod\b|backdoor", re.IGNORECASE), "shell_command"),
    (re.compile(rb"(?:password|passwd|api[_-]?key|secret)\s*=", re.IGNORECASE), "credential_pattern"),
    (re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "embedded_ip"),
    (re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}"), "base64_blob"),
]

# --------------------------------------------------------------------------
# Additive scoring weights (see the confidence table in the module
# docstring's parent task spec). Kept as module-level constants rather
# than config.py entries, mirroring modules/entropy.py's own local
# `_SEVERITY_RANK` / `_REGION_PLOT_COLORS` constants -- these are scoring
# mechanics, not detection thresholds a user would retune per firmware.
# --------------------------------------------------------------------------
_SCORE_PUBLIC_NON_BENIGN_PORT = 30
_SCORE_PER_SUSPICIOUS_STRING = 25
_SCORE_SUSPICIOUS_STRING_CAP = 50
_SCORE_HIGH_ENTROPY_PAYLOAD = 20
_SCORE_SUSPICIOUS_SNI = 25
_SCORE_REPEATED_CONNECTION = 20
_SCORE_REGULAR_BEACON = 30
_SCORE_DNS_ANOMALY = 35
_SCORE_BENIGN_PORT_ADJUST = -20
_SCORE_KNOWN_CLOUD_ADJUST = -15

_SEVERITY_CRITICAL_THRESHOLD = 80
_SEVERITY_HIGH_THRESHOLD = 60
_SEVERITY_MEDIUM_THRESHOLD = 35
_SEVERITY_LOW_THRESHOLD = 10

# Beacon timing is "regular" when interval standard deviation is under
# this fraction of the mean interval -- real malware beacons on a clock,
# random legitimate traffic does not.
_BEACON_REGULARITY_RATIO = 0.20

# TLS handshake ContentType byte -- present at the start of any real TLS
# record even when scapy's TLS layer doesn't fully dissect it.
_TLS_HANDSHAKE_CONTENT_TYPE = 0x16


@dataclass
class _Connection:
    """One grouped (src_ip, dst_ip, dst_port, protocol) connection.

    Attributes:
        src_ip: Source IP address string.
        dst_ip: Destination IP address string.
        dst_port: Destination port number.
        protocol: "TCP" or "UDP".
        packets: All packets belonging to this connection, in capture order.
    """

    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    packets: list = field(default_factory=list)


def _severity_for_score(score: int) -> Optional[str]:
    """Map an additive suspicion score to a Finding severity.

    Args:
        score: Additive suspicion score (see module-level `_SCORE_*`
            constants).

    Returns:
        "critical", "high", "medium", or "low", or None if the score is
        below the reporting floor and should not become a Finding.

    Raises:
        None.
    """
    if score >= _SEVERITY_CRITICAL_THRESHOLD:
        return "critical"
    if score >= _SEVERITY_HIGH_THRESHOLD:
        return "high"
    if score >= _SEVERITY_MEDIUM_THRESHOLD:
        return "medium"
    if score >= _SEVERITY_LOW_THRESHOLD:
        return "low"
    return None


def _is_private_destination(dst_ip: str) -> bool:
    """Check whether a destination IP is private/local traffic.

    Args:
        dst_ip: Destination IP address string.

    Returns:
        True if `dst_ip` is a private, loopback, or link-local address
        (RFC 1918, 127.0.0.0/8, 169.254.0.0/16), or if it cannot be
        parsed as an IP address at all (treated conservatively as not
        worth analyzing). False for any other public address.

    Raises:
        None.
    """
    try:
        return ipaddress.ip_address(dst_ip).is_private
    except ValueError:
        return True


def _is_known_cloud_range(dst_ip: str) -> bool:
    """Check whether a destination IP falls in a known cloud-provider range.

    Args:
        dst_ip: Destination IP address string.

    Returns:
        True if `dst_ip` starts with any prefix in
        `config.NETWORK_MONITOR_KNOWN_CLOUD_RANGES`.

    Raises:
        None.
    """
    return any(dst_ip.startswith(prefix) for prefix in config.NETWORK_MONITOR_KNOWN_CLOUD_RANGES)


def _group_connections(packets: list) -> Dict[Tuple[str, str, int, str], _Connection]:
    """Group packets into connections by (src_ip, dst_ip, dst_port, protocol).

    Args:
        packets: All packets in the capture (post-defrag).

    Returns:
        Dict mapping each connection tuple to its `_Connection`. Packets
        without an IP layer, or without a TCP/UDP layer, are skipped --
        there is no meaningful destination port to group them by.

    Raises:
        None.
    """
    connections: Dict[Tuple[str, str, int, str], _Connection] = {}
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        ip_layer = pkt[IP]
        if pkt.haslayer(TCP):
            protocol = "TCP"
            dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            dst_port = int(pkt[UDP].dport)
        else:
            continue

        key = (ip_layer.src, ip_layer.dst, dst_port, protocol)
        connection = connections.setdefault(
            key, _Connection(ip_layer.src, ip_layer.dst, dst_port, protocol)
        )
        connection.packets.append(pkt)
    return connections


def _is_tls_encrypted(packets: list) -> bool:
    """Check for a genuine TLS handshake, not just traffic on port 443.

    Args:
        packets: All packets in one connection.

    Returns:
        True if any packet carries a dissected TLS layer, or its raw
        payload begins with the TLS handshake ContentType byte (0x16) --
        plaintext traffic on port 443 will match neither and is treated
        as ordinary plaintext.

    Raises:
        None.
    """
    for pkt in packets:
        if pkt.haslayer(TLS):
            return True
        if pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            if load and load[0] == _TLS_HANDSHAKE_CONTENT_TYPE:
                return True
    return False


def _extract_sni(packets: list) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello, if present.

    The SNI extension is sent unencrypted (it's needed for routing before
    the handshake completes), so it's the one piece of a TLS connection
    still visible for inspection.

    Args:
        packets: All packets in one connection.

    Returns:
        The server name from the first ClientHello found, or None if no
        ClientHello with an SNI extension is present.

    Raises:
        None.
    """
    for pkt in packets:
        if not pkt.haslayer(TLSClientHello):
            continue
        try:
            for ext in pkt[TLSClientHello].ext:
                servernames = getattr(ext, "servernames", None)
                if servernames:
                    return servernames[0].servername.decode(errors="replace")
        except (AttributeError, IndexError, UnicodeDecodeError):
            continue
    return None


def _sni_is_suspicious(hostname: str) -> bool:
    """Check a TLS SNI hostname for tunneling-style anomalies.

    Args:
        hostname: SNI hostname extracted from a ClientHello.

    Returns:
        True if the hostname's subdomain portion is unusually long or
        unusually high-entropy -- the same heuristics used for DNS
        tunneling detection, since an encrypted-C2 client can encode
        data in the hostname it connects to just as easily as in a DNS
        query.

    Raises:
        None.
    """
    labels = hostname.split(".")
    if len(labels) <= 2:
        return False
    subdomain = ".".join(labels[:-2])
    if len(subdomain) > 40:
        return True
    return shannon_entropy(subdomain.encode()) > config.NETWORK_MONITOR_DNS_ENTROPY_THRESHOLD


def _match_suspicious_strings(payload: bytes) -> List[str]:
    """Match a payload against the suspicious-string pattern categories.

    Args:
        payload: Concatenated raw payload bytes from one connection.

    Returns:
        List of "category:match" strings, one per match found across all
        categories (see `_SUSPICIOUS_STRING_PATTERNS`).

    Raises:
        None.
    """
    matches: List[str] = []
    for pattern, category in _SUSPICIOUS_STRING_PATTERNS:
        for match in pattern.findall(payload):
            matches.append(f"{category}:{match.decode(errors='replace')}")
    return matches


def _analyze_connection(
    key: Tuple[str, str, int, str], connection: _Connection
) -> Optional[Finding]:
    """Score one connection and build its Finding if suspicious enough.

    Args:
        key: The (src_ip, dst_ip, dst_port, protocol) connection tuple.
        connection: The grouped `_Connection` to analyze.

    Returns:
        A Finding if the connection's additive suspicion score reaches
        the reporting floor, else None (including for private/local
        destinations, which are skipped outright).

    Raises:
        None.
    """
    src_ip, dst_ip, dst_port, protocol = key
    if _is_private_destination(dst_ip):
        return None

    score = 0
    signals: List[str] = []

    is_benign_port = dst_port in config.NETWORK_MONITOR_BENIGN_PORTS
    if is_benign_port:
        score += _SCORE_BENIGN_PORT_ADJUST
        signals.append(f"benign_port:{dst_port}")
    else:
        score += _SCORE_PUBLIC_NON_BENIGN_PORT
        signals.append("public_ip_non_benign_port")

    if _is_known_cloud_range(dst_ip):
        score += _SCORE_KNOWN_CLOUD_ADJUST
        signals.append("known_cloud_range")
        logger.debug(
            "Destination %s matches a known cloud-provider range; reducing suspicion "
            "score (cannot reliably distinguish from CDN-routed C2 at this level)",
            dst_ip,
        )

    is_tls = _is_tls_encrypted(connection.packets)
    sni_hostname: Optional[str] = None
    payload_sample: Optional[str] = None
    payload_entropy: Optional[float] = None
    suspicious_strings: List[str] = []

    if is_tls:
        logger.debug(
            "TLS detected on connection %s:%d -- skipping payload inspection, "
            "extracting SNI",
            dst_ip,
            dst_port,
        )
        sni_hostname = _extract_sni(connection.packets)
        if sni_hostname and _sni_is_suspicious(sni_hostname):
            score += _SCORE_SUSPICIOUS_SNI
            signals.append(f"suspicious_sni:{sni_hostname}")
    else:
        payload = b"".join(
            bytes(pkt[Raw].load) for pkt in connection.packets if pkt.haslayer(Raw)
        )
        if payload:
            payload_sample = payload[:200].decode(errors="replace")
            payload_entropy = shannon_entropy(payload)
            suspicious_strings = _match_suspicious_strings(payload)
            if suspicious_strings:
                score += min(
                    _SCORE_PER_SUSPICIOUS_STRING * len(suspicious_strings),
                    _SCORE_SUSPICIOUS_STRING_CAP,
                )
                signals.append(f"suspicious_string_match:{len(suspicious_strings)}")
            if payload_entropy > config.NETWORK_MONITOR_PAYLOAD_ENTROPY_THRESHOLD:
                score += _SCORE_HIGH_ENTROPY_PAYLOAD
                signals.append("high_entropy_plaintext_payload")

    timestamps = sorted(float(pkt.time) for pkt in connection.packets)
    is_repeated = False
    is_regular_beacon = False
    beacon_interval: Optional[float] = None
    if len(timestamps) >= config.NETWORK_MONITOR_BEACON_REPEAT_THRESHOLD:
        is_repeated = True
        score += _SCORE_REPEATED_CONNECTION
        signals.append(f"repeated_connection:{len(timestamps)}x")

        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        if mean_interval > 0 and std_interval < mean_interval * _BEACON_REGULARITY_RATIO:
            is_regular_beacon = True
            beacon_interval = mean_interval
            score += _SCORE_REGULAR_BEACON
            signals.append("regular_beacon_timing")

    severity = _severity_for_score(score)
    if severity is None:
        return None

    raw = {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "protocol": protocol,
        "packet_count": len(connection.packets),
        "is_tls_encrypted": is_tls,
        "sni_hostname": sni_hostname,
        "payload_sample": payload_sample,
        "payload_entropy": payload_entropy,
        "suspicious_strings_found": suspicious_strings,
        "is_repeated": is_repeated,
        "is_regular_beacon": is_regular_beacon,
        "beacon_interval_seconds": beacon_interval,
        "confidence_score": score,
        "signals_fired": signals,
    }
    return Finding(
        module_name=MODULE_NAME,
        severity=severity,
        offset=None,
        description=(
            f"Suspicious connection {src_ip} -> {dst_ip}:{dst_port}/{protocol} "
            f"(score={score}): {'; '.join(signals)}"
        ),
        evidence=f"{len(connection.packets)} packet(s); signals: {', '.join(signals)}",
        score=config.SEVERITY_SCORE_WEIGHTS[severity],
        raw=raw,
    )


def _dns_queries(packets: list) -> Dict[str, int]:
    """Count DNS query occurrences per domain across the whole capture.

    Args:
        packets: All packets in the capture.

    Returns:
        Dict mapping each queried domain (trailing dot stripped) to the
        number of times it was queried.

    Raises:
        None.
    """
    counts: Dict[str, int] = defaultdict(int)
    for pkt in packets:
        if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            continue
        if pkt[DNS].qr != 0:
            continue  # response, not a query
        qname = pkt[DNSQR].qname
        domain = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
        domain = domain.rstrip(".")
        if domain:
            counts[domain] += 1
    return counts


def _analyze_dns(packets: list) -> List[Finding]:
    """Feature 3: flag DNS-tunneling-style anomalies across the capture.

    Processed independently of TCP/UDP connection grouping -- a DNS
    tunnel is a property of the query stream, not of any single
    connection tuple.

    Args:
        packets: All packets in the capture.

    Returns:
        One Finding per domain with at least one anomaly (long
        subdomain, high-entropy subdomain, or repeated beyond
        `config.NETWORK_MONITOR_DNS_REPEAT_THRESHOLD`).

    Raises:
        None.
    """
    findings: List[Finding] = []
    for domain, count in _dns_queries(packets).items():
        labels = domain.split(".")
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""

        reasons: List[str] = []
        if len(subdomain) > 40:
            reasons.append(f"subdomain length {len(subdomain)} exceeds 40 chars")
        subdomain_entropy = shannon_entropy(subdomain.encode()) if subdomain else 0.0
        if subdomain and subdomain_entropy > config.NETWORK_MONITOR_DNS_ENTROPY_THRESHOLD:
            reasons.append(f"subdomain entropy {subdomain_entropy:.2f} exceeds threshold")
        if count > config.NETWORK_MONITOR_DNS_REPEAT_THRESHOLD:
            reasons.append(f"queried {count} times")

        if not reasons:
            continue

        severity = _severity_for_score(_SCORE_DNS_ANOMALY)
        findings.append(
            Finding(
                module_name=MODULE_NAME,
                severity=severity,
                offset=None,
                description=f"DNS anomaly for {domain!r}: {'; '.join(reasons)}",
                evidence=domain,
                score=config.SEVERITY_SCORE_WEIGHTS[severity],
                raw={
                    "query_domain": domain,
                    "subdomain": subdomain,
                    "subdomain_length": len(subdomain),
                    "subdomain_entropy": subdomain_entropy,
                    "query_count": count,
                    "confidence_score": _SCORE_DNS_ANOMALY,
                    "signals_fired": reasons,
                },
            )
        )
    return findings


def _read_packets(pcap_path: Path) -> list:
    """Read and defragment a pcap file, falling back to a streaming reader.

    Args:
        pcap_path: Path to the capture file.

    Returns:
        List of (defragmented, where applicable) packets.

    Raises:
        AnalysisError: If the file cannot be parsed as a pcap by either
            the primary or fallback reader.
    """
    try:
        try:
            raw_packets = rdpcap(str(pcap_path))
            # scapy's defrag() returns a 3-tuple -- ([not fragmented],
            # [defragmented], [bad fragment groups]) -- not the 2-tuple a
            # naive `packets, _ = defrag(...)` would assume; verified
            # directly against scapy 2.5.0. Bad/incomplete fragment
            # groups are dropped: there's nothing coherent left to
            # inspect in them.
            not_fragmented, defragmented, _bad_fragments = defrag(raw_packets)
            packets = list(not_fragmented) + list(defragmented)
        except Exception:
            logger.debug(
                "rdpcap/defrag failed for %s; falling back to streaming reader", pcap_path
            )
            packets = list(PcapReader(str(pcap_path)))
    except Exception as exc:
        raise AnalysisError(f"Failed to parse capture file {pcap_path} as a pcap: {exc}") from exc
    return packets


def analyze(pcap_path: str) -> List[Finding]:
    """Analyze a network capture for suspicious firmware C2 communication.

    Detects: suspicious destinations, malicious payload content,
    encrypted C2 patterns, DNS tunneling, and beacon timing. Works
    against real captures or synthetically generated pcap files.

    Args:
        pcap_path: Path to a .pcap or .pcapng capture file.

    Returns:
        List of Finding objects sorted by confidence descending. One
        Finding per suspicious destination or anomalous DNS domain, not
        per packet.

    Raises:
        FileNotFoundError: If pcap_path does not exist.
        AnalysisError: If the file cannot be parsed as a valid pcap.
    """
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"Capture file not found: {pcap_path}")

    packets = _read_packets(path)
    if not packets:
        logger.info("capture file contains no packets -- nothing to analyze")
        return []

    logger.info("Analyzing %s (%d packet(s))", path, len(packets))

    connections = _group_connections(packets)
    findings: List[Finding] = []
    suspicious_connections = 0
    for key, connection in connections.items():
        finding = _analyze_connection(key, connection)
        if finding is not None:
            findings.append(finding)
            suspicious_connections += 1

    findings.extend(_analyze_dns(packets))

    findings.sort(key=lambda f: f.raw.get("confidence_score", 0), reverse=True)

    if findings:
        findings[0].raw["network_summary"] = {
            "total_packets": len(packets),
            "total_connections": len(connections),
            "suspicious_connections": suspicious_connections,
            "clean_connections": len(connections) - suspicious_connections,
        }

    logger.info(
        "Network analysis complete: %d finding(s) across %d connection(s)",
        len(findings),
        len(connections),
    )
    return findings


def _write_report(pcap_path: Path, findings: List[Finding], output_dir: Path) -> Path:
    """Write findings to a timestamped JSON report, matching main.py's format.

    Args:
        pcap_path: The capture file that was analyzed (used only for
            logging context; the report filename is module-scoped, not
            per-input, matching the CLI spec).
        findings: Findings returned by `analyze()`.
        output_dir: Directory to write the report into (created if
            missing).

    Returns:
        Path to the written report file.

    Raises:
        None.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"report_{MODULE_NAME}_{timestamp}.json"
    report_data = [asdict(finding) for finding in findings]
    with report_path.open("w", encoding="utf-8") as report_file:
        json.dump(report_data, report_file, indent=2)
    logger.debug("Wrote %s (analyzed %s)", report_path, pcap_path)
    return report_path


def _main() -> None:
    """Command-line entry point for standalone module execution.

    Allows `python -m modules.dynamic.network_monitor capture.pcap` to run
    network analysis and print a human-readable summary. This is the only
    place in this module that writes to stdout -- `analyze()` itself never
    prints, so importing this module has no side effects.

    Args:
        None. Arguments are read from sys.argv via argparse.

    Returns:
        None.

    Raises:
        SystemExit: If the capture file argument is missing/invalid, or
            if analysis fails.
    """
    parser = argparse.ArgumentParser(
        description="Analyze a pcap capture for suspicious firmware C2 traffic."
    )
    parser.add_argument("pcap_path", help="Path to a .pcap or .pcapng capture file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )

    try:
        findings = analyze(args.pcap_path)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)
    except AnalysisError as exc:
        logger.error("Network analysis failed: %s", exc)
        sys.exit(1)

    if not findings:
        print("No suspicious network activity detected.")
    else:
        print(f"Detected {len(findings)} suspicious connection(s)/anomaly(ies):")
        for finding in findings:
            location = finding.raw.get("query_domain")
            if location is None:
                location = f"{finding.raw['destination_ip']}:{finding.raw['destination_port']}"
            print(
                f"  [{finding.severity.upper()}] {location} "
                f"score={finding.score} - {finding.description}"
            )

    report_path = _write_report(Path(args.pcap_path), findings, config.DEFAULT_OUTPUT_DIR)
    print(f"\nFull report written to: {report_path}")


if __name__ == "__main__":
    _main()
