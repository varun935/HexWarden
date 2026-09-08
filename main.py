"""Command-line entry point for the HexWarden firmware analysis toolkit.

Parses CLI arguments, selects which analysis modules to run, invokes each
module's `analyze()` function, and prints a human-readable summary of
findings. This file is the intended exception to the "no direct stdout
printing" rule that governs analysis modules, since CLI output is its
explicit purpose.

Inputs:
    Command-line arguments:
        --firmware PATH   Path to the firmware binary to analyze (required).
        --golden PATH     Path to a known-clean reference firmware, for
                           golden-image diff (optional; only used if
                           "golden_diff" is in --modules).
        --output DIR      Directory to write reports/plots to (optional).
        --modules LIST    Comma-separated list of modules to enable (optional).
        --verbose         Enable debug-level logging (optional flag).

Outputs:
    A human-readable findings summary printed to stdout. Process exit code
    0 on success (even when findings are present), non-zero on error.
"""

import argparse
import json
import logging
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import config
from core import AnalysisError, Finding
from modules import entropy, filesystem, firmware_pipeline, golden_diff

logger = logging.getLogger(__name__)

# Mapping of CLI module names to their analysis callables. Only modules
# that have been implemented so far are listed here; unimplemented
# modules from config.ENABLED_MODULES are intentionally omitted until
# they are built out. "pipeline" runs entropy plus recursive Binwalk
# extraction, and -- now that filesystem.py is wired into
# firmware_pipeline.py -- filesystem checks against that same extraction
# too, automatically; "entropy" remains available standalone for a
# raw-binary-only scan with no extraction step. "golden_diff" is listed
# here for CLI help/validation purposes only -- it takes (golden, suspect)
# rather than a single firmware path, so `run()` special-cases its
# invocation instead of calling it through the generic single-argument
# loop below. "filesystem" is registered per the same generic pattern for
# standalone/isolated use (`python -m modules.filesystem <dir>` remains
# the direct entry point -- it still expects an *extracted directory*,
# not a firmware file, so running it here via `--firmware` will fail with
# a clear FileNotFoundError); in normal use, running "pipeline" already
# includes filesystem checks, so `--modules filesystem` on its own is not
# the primary way to get them.
_AVAILABLE_MODULES = {
    "entropy": entropy.analyze,
    "pipeline": firmware_pipeline.run_pipeline,
    "golden_diff": golden_diff.analyze_diff,
    "filesystem": filesystem.analyze,
}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse command-line arguments for the HexWarden CLI.

    Args:
        argv: Argument strings, typically `sys.argv[1:]`.

    Returns:
        Parsed namespace with `firmware`, `output`, `modules`, and
        `verbose` attributes.

    Raises:
        SystemExit: If required arguments are missing or invalid.
    """
    parser = argparse.ArgumentParser(
        prog="hexwarden",
        description="HexWarden: firmware trojan/malware analysis toolkit.",
    )
    parser.add_argument(
        "--firmware", required=True, help="Path to the firmware binary to analyze."
    )
    parser.add_argument(
        "--golden",
        default=None,
        help=(
            "Path to a known-clean reference firmware image, for golden-image "
            "diff (Mode A). Only used if 'golden_diff' is included in --modules; "
            "if omitted, golden_diff is skipped."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(config.DEFAULT_OUTPUT_DIR),
        help="Directory to write reports and plots to.",
    )
    parser.add_argument(
        "--modules",
        default="pipeline",
        help=(
            "Comma-separated list of modules to run. "
            f"Available: {', '.join(sorted(_AVAILABLE_MODULES))}."
        ),
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug-level logging.")
    return parser.parse_args(argv)


def _configure_logging(verbose: bool) -> None:
    """Configure root logging for the CLI run.

    Args:
        verbose: If True, set log level to DEBUG, otherwise INFO.

    Returns:
        None.

    Raises:
        None.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=config.LOG_FORMAT,
    )
    # matplotlib's font manager (used by modules/entropy.py's plotting) emits
    # thousands of DEBUG lines while resolving fonts, burying real pipeline
    # logs under --verbose; Pillow is similarly chatty. Neither is relevant
    # to firmware analysis, so keep them at WARNING regardless of verbosity.
    logging.getLogger("matplotlib").setLevel(logging.WARNING)
    logging.getLogger("PIL").setLevel(logging.WARNING)


def _resolve_modules(module_list: str) -> List[str]:
    """Resolve and validate the comma-separated `--modules` argument.

    Args:
        module_list: Raw comma-separated module names from the CLI.

    Returns:
        List of validated module names that are both requested and
        available.

    Raises:
        AnalysisError: If none of the requested modules are available.
    """
    requested = [name.strip() for name in module_list.split(",") if name.strip()]
    resolved = [name for name in requested if name in _AVAILABLE_MODULES]

    unavailable = set(requested) - set(resolved)
    if unavailable:
        logger.warning("Ignoring unavailable module(s): %s", ", ".join(sorted(unavailable)))

    if not resolved:
        raise AnalysisError("No available modules were selected to run.")

    return resolved


def run(argv: Sequence[str]) -> int:
    """Run the HexWarden CLI end-to-end.

    Args:
        argv: Argument strings, typically `sys.argv[1:]`.

    Returns:
        Process exit code: 0 on success, 1 on error.

    Raises:
        None. All expected exceptions are caught and converted to exit
        codes.
    """
    args = parse_args(argv)
    _configure_logging(args.verbose)

    try:
        module_names = _resolve_modules(args.modules)
    except AnalysisError as exc:
        logger.error("%s", exc)
        return 1

    firmware_path = Path(args.firmware)
    config.DEFAULT_OUTPUT_DIR = Path(args.output)

    all_findings: List[Finding] = []
    for module_name in module_names:
        if module_name == "golden_diff":
            if not args.golden:
                logger.info(
                    "No golden reference provided (--golden) — skipping golden-image "
                    "diff, using heuristic pipeline only."
                )
                continue
            logger.info("Running module: golden_diff")
            try:
                findings = golden_diff.analyze_diff(args.golden, str(firmware_path))
            except FileNotFoundError as exc:
                logger.error("%s", exc)
                return 1
            except AnalysisError as exc:
                logger.error("Module 'golden_diff' failed: %s", exc)
                continue
            all_findings.extend(findings)
            continue

        analyze_fn = _AVAILABLE_MODULES[module_name]
        logger.info("Running module: %s", module_name)
        try:
            findings = analyze_fn(str(firmware_path))
        except FileNotFoundError as exc:
            logger.error("%s", exc)
            return 1
        except AnalysisError as exc:
            logger.error("Module '%s' failed: %s", module_name, exc)
            continue
        all_findings.extend(findings)

    report_path: Optional[Path] = None
    if all_findings:
        try:
            report_path = _write_report(firmware_path, all_findings, config.DEFAULT_OUTPUT_DIR)
        except AnalysisError as exc:
            logger.warning("Could not write full findings report: %s", exc)

    _print_summary(firmware_path, all_findings, report_path)
    return 0


def _write_report(firmware_path: Path, findings: List[Finding], output_dir: Path) -> Path:
    """Write the complete list of findings to a JSON report file.

    The terminal summary only ever shows the highest-scoring findings, so
    this file is the source of truth for the full result set (see
    `_print_summary`).

    Args:
        firmware_path: Path to the analyzed firmware file (used for
            naming the report file).
        findings: All findings collected across enabled modules.
        output_dir: Directory to write the report file into.

    Returns:
        Path to the written JSON report file.

    Raises:
        AnalysisError: If the report directory or file cannot be written.
    """
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = output_dir / f"report_{firmware_path.stem}_{timestamp}.json"
        report_data = [asdict(finding) for finding in findings]
        with report_path.open("w", encoding="utf-8") as report_file:
            json.dump(report_data, report_file, indent=2)
        return report_path
    except OSError as exc:
        raise AnalysisError(f"Failed to write report to {output_dir}: {exc}") from exc


def _pipeline_breakdown(findings: List[Finding]) -> Optional[Tuple[int, int, int]]:
    """Compute expected/suspicious/anomaly counts for pipeline findings.

    Args:
        findings: All findings collected across enabled modules.

    Returns:
        An (expected_count, suspicious_count, anomaly_count) tuple if at
        least one finding carries `firmware_pipeline`'s
        `expected_high_entropy` raw-dict field, or None if none do (e.g.
        the `entropy` module was run standalone, without `pipeline`).

    Raises:
        None.
    """
    pipeline_findings = [finding for finding in findings if "expected_high_entropy" in finding.raw]
    if not pipeline_findings:
        return None

    categories = [firmware_pipeline.categorize_finding(finding) for finding in pipeline_findings]
    return (
        categories.count("expected"),
        categories.count("suspicious"),
        categories.count("anomaly"),
    )


def _print_summary(
    firmware_path: Path, findings: List[Finding], report_path: Optional[Path]
) -> None:
    """Print a compact human-readable summary of findings to stdout.

    Shows a count of findings per severity plus the highest-scoring
    findings (capped at `config.CLI_SUMMARY_TOP_N`), rather than every
    finding, since a single scan can produce hundreds of results. The
    complete list is available in the file at `report_path`.

    Args:
        firmware_path: Path to the analyzed firmware file.
        findings: All findings collected across enabled modules.
        report_path: Path to the full JSON report, or None if no report
            was written (e.g. no findings, or the write failed).

    Returns:
        None.

    Raises:
        None.
    """
    print(f"\nHexWarden analysis report: {firmware_path}")
    print("=" * 60)

    if not findings:
        print("No suspicious indicators detected.")
        return

    severity_counts = Counter(finding.severity for finding in findings)
    for severity in ("critical", "high", "medium", "low"):
        if severity_counts[severity]:
            print(f"  {severity.upper():>8}: {severity_counts[severity]}")

    breakdown = _pipeline_breakdown(findings)
    if breakdown is not None:
        expected_count, suspicious_count, anomaly_count = breakdown
        print(f"  Expected (labeled): {expected_count}")
        print(f"  Suspicious (unexplained): {suspicious_count}")
        print(f"  Format anomalies: {anomaly_count}")

    top_findings = sorted(findings, key=lambda item: item.score, reverse=True)
    top_findings = top_findings[: config.CLI_SUMMARY_TOP_N]

    print("-" * 60)
    print(f"Top {len(top_findings)} finding(s) by score:")
    for finding in top_findings:
        offset_str = f"offset={finding.offset}" if finding.offset is not None else "offset=N/A"
        print(
            f"  [{finding.severity.upper():>8}] ({finding.module_name}) "
            f"{offset_str} score={finding.score} - {finding.description}"
        )

    print("=" * 60)
    print(f"Total findings: {len(findings)} (combined raw score: {sum(f.score for f in findings)})")
    if report_path is not None:
        print(f"Full report written to: {report_path}")


def main() -> None:
    """Entry point invoked by the `hexwarden` console script and `python main.py`.

    Args:
        None.

    Returns:
        None.

    Raises:
        SystemExit: Propagates the process exit code from `run()`.
    """
    sys.exit(run(sys.argv[1:]))


if __name__ == "__main__":
    main()
