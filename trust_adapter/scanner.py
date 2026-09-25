"""POC firmware trust scanner backed by the existing HexWarden pipeline.

The trust adapter intentionally has a small contract: HexWarden produces a
demonstration verdict and SHA-256; the blockchain later records only CLEAN
firmware. Detection remains off-chain and this module does not claim that the
ledger detects malware.
"""

from pathlib import Path
from typing import Any, Union

from .hasher import sha256_file


def _reasons(findings: list[Any]) -> list[str]:
    return [
        f"{finding.module_name}: {finding.description}"
        for finding in findings
        if finding.severity in {"critical", "high", "medium"}
    ][:10]


def analyze_firmware(path: Union[str, Path]) -> dict[str, Any]:
    """Analyze one firmware file and return a JSON-friendly trust result.

    A file is CLEAN when the existing pipeline has no medium-or-higher risk
    findings. This is a POC policy, not a substitute for a lab's review.
    """
    firmware_path = Path(path)
    if not firmware_path.is_file():
        raise FileNotFoundError(f"Firmware file not found: {firmware_path}")

    findings: list[Any] = []
    analysis_mode = "existing-pipeline"
    try:
        from core.scoring import score
        from modules import firmware_pipeline

        findings = firmware_pipeline.run_pipeline(str(firmware_path))
        risk = score(findings, modules_run=["pipeline"])
        reasons = _reasons(findings)
    except (ImportError, OSError):
        # Optional native analyzers such as YARA may be unavailable on a
        # developer machine. Keep the POC usable with conservative markers.
        analysis_mode = "basic-fallback"
        data = firmware_path.read_bytes()
        markers = (b"reverse_shell", b"/bin/sh", b"trojan", b"suspicious")
        reasons = ["basic marker match: demonstration suspicious content"] if any(
            marker in data.lower() for marker in markers
        ) else []
        risk = type("BasicRisk", (), {"total_score": 90 if reasons else 0})()
    verdict = "CLEAN" if risk.total_score < 26 and not reasons else "BAD"
    return {
        "verdict": verdict,
        "reasons": reasons,
        "sha256": sha256_file(firmware_path),
        "score": risk.total_score,
        "finding_count": len(findings),
        "analysis_mode": analysis_mode,
    }