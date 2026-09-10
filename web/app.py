"""Flask web dashboard for HexWarden.

Wraps the existing analysis modules in a browser UI: upload firmware
(plus optional golden reference and pcap capture), watch progress over
Server-Sent Events while a background thread runs the pipeline, then
browse a scored, corroborated findings report.

No existing module is modified to make this work. Two integration gaps
are bridged entirely in this file:

    1. `modules/yara_engine.py` predates `core.Finding` and defines its
       own, differently-shaped `Finding` dataclass (see
       `_yara_finding_to_core()`). Everything else in the codebase
       already uses `core.Finding`.
    2. `modules/firmware_pipeline.py`'s `run_pipeline()` saves a combined
       entropy plot as a side effect but doesn't return its path. The
       filename pattern is stable (`entropy_<stem>_<timestamp>.png` in
       `config.DEFAULT_OUTPUT_DIR`), so `_locate_entropy_plot()` finds it
       by globbing for the newest match created during the scan.

Per module in the pipeline is wrapped so a single module's exception
(bad input, a missing optional dependency, a third-party library bug)
never aborts the rest of the scan -- it's logged and treated as "this
module produced no findings" instead.

Inputs:
    HTTP requests (multipart firmware/golden/pcap uploads, scan status
    polling, SSE subscriptions).

Outputs:
    Rendered dashboard/report HTML, JSON scan status/report responses,
    and an SSE progress stream per scan.
"""

import json
import logging
import queue
import shutil
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template,
    request,
    send_file,
    stream_with_context,
)
from flask_cors import CORS
from werkzeug.utils import secure_filename

import config
from core import Finding
from core.scoring import score as score_findings
from modules import firmware_pipeline, golden_diff, strings, yara_engine
from modules.dynamic import network_monitor
from web import database

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config["SECRET_KEY"] = config.WEB_SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.WEB_MAX_FIRMWARE_SIZE_MB * 1024 * 1024
CORS(app)

# One SSE queue per in-flight (or completed) scan. Kept for the process's
# lifetime rather than pruned after completion -- a stream reconnecting
# after the terminal event just re-reads scan status from the database
# instead (see `scan_stream()`), and the memory cost of a handful of
# small Queue objects for a dashboard's lifetime is negligible.
_scan_queues: Dict[str, "queue.Queue"] = {}
_scan_queues_lock = threading.Lock()

_YARA_RULES_DIR = config.PROJECT_ROOT / "rules"


def _get_queue(scan_id: str) -> "queue.Queue":
    """Get (creating if needed) the SSE event queue for a scan.

    Args:
        scan_id: UUID identifying the scan.

    Returns:
        The scan's `queue.Queue`, shared across the pipeline thread
        (producer) and any connected `/stream` requests (consumers).

    Raises:
        None.
    """
    with _scan_queues_lock:
        if scan_id not in _scan_queues:
            _scan_queues[scan_id] = queue.Queue()
        return _scan_queues[scan_id]


def _emit(scan_id: str, step: str, progress: int, **extra) -> None:
    """Push one progress event onto a scan's SSE queue and persist the step.

    Args:
        scan_id: UUID identifying the scan.
        step: Human-readable current step description.
        progress: 0-100 progress percentage.
        **extra: Additional fields merged into the event (e.g.
            `complete`, `verdict`, `score`, `error`).

    Returns:
        None.

    Raises:
        None.
    """
    database.update_scan_step(scan_id, step)
    event = {"step": step, "progress": progress, "complete": False, **extra}
    _get_queue(scan_id).put(event)


def _sse_format(event: dict) -> str:
    """Format one event dict as an SSE `data:` frame.

    Args:
        event: JSON-serializable event dict.

    Returns:
        The SSE wire-format frame, including the trailing blank line.

    Raises:
        None.
    """
    return f"data: {json.dumps(event)}\n\n"


def _yara_finding_to_core(yara_finding: yara_engine.Finding) -> Finding:
    """Adapt a modules/yara_engine.py Finding to core.Finding.

    yara_engine.py predates core.Finding and uses its own schema (see
    module docstring). Everything specific to YARA (rule name, tags,
    matched strings, baseline-suppression state) is preserved in `raw`.

    Args:
        yara_finding: A finding from `YaraEngine.scan_file()`.

    Returns:
        The equivalent `core.Finding`.

    Raises:
        None.
    """
    severity = yara_finding.severity if yara_finding.severity in config.SEVERITY_SCORE_WEIGHTS else "info"
    return Finding(
        module_name="yara_engine",
        severity=severity,
        offset=yara_finding.offset,
        description=yara_finding.description or f"YARA rule {yara_finding.rule!r} matched",
        evidence=yara_finding.rule,
        score=config.SEVERITY_SCORE_WEIGHTS.get(severity, 0),
        raw={
            "rule": yara_finding.rule,
            "namespace": yara_finding.namespace,
            "category": yara_finding.category,
            "file_path": yara_finding.file_path,
            "file_sha256": yara_finding.file_sha256,
            "tags": yara_finding.tags,
            "meta": yara_finding.meta,
            "matched_strings": [
                {"identifier": s.identifier, "offset": s.offset, "preview": s.preview}
                for s in yara_finding.strings
            ],
        },
    )


def _safe_run(step_name: str, func, *args, **kwargs) -> List[Finding]:
    """Run one module's analyze call, never letting it abort the scan.

    Args:
        step_name: Human-readable name for logging.
        func: The module's callable (e.g. `strings.analyze`).
        *args: Positional arguments for `func`.
        **kwargs: Keyword arguments for `func`.

    Returns:
        `func`'s findings, or an empty list if it raised anything --
        the failure is logged, never propagated.

    Raises:
        None.
    """
    try:
        return list(func(*args, **kwargs))
    except FileNotFoundError:
        raise  # a missing *uploaded* file means the scan itself is broken, not one module
    except Exception:
        logger.exception("%s failed; continuing with the rest of the pipeline", step_name)
        return []


def _locate_entropy_plot(firmware_path: Path, started_at: float) -> Optional[str]:
    """Find the entropy plot PNG that firmware_pipeline.run_pipeline() just saved.

    `run_pipeline()` saves a combined entropy plot as a side effect but
    doesn't return its path (see module docstring). The filename pattern
    is stable, so this globs for it and picks the newest match created
    at or after this scan started.

    Args:
        firmware_path: The firmware file that was analyzed.
        started_at: `time.time()` value recorded just before the
            pipeline ran, used to ignore stale plots from a previous scan
            of a same-named file.

    Returns:
        String path to the plot PNG, or None if no matching file is
        found.

    Raises:
        None.
    """
    pattern = f"entropy_{firmware_path.stem}_*.png"
    candidates = [
        candidate
        for candidate in config.DEFAULT_OUTPUT_DIR.glob(pattern)
        if candidate.stat().st_mtime >= started_at - 1
    ]
    if not candidates:
        return None
    newest = max(candidates, key=lambda candidate: candidate.stat().st_mtime)
    return str(newest)


def run_pipeline_for_scan(
    scan_id: str, firmware_path: Path, golden_path: Optional[Path], pcap_path: Optional[Path]
) -> None:
    """Run the full analysis pipeline for one scan in a background thread.

    Args:
        scan_id: UUID identifying the scan.
        firmware_path: Path to the uploaded firmware file.
        golden_path: Path to the uploaded golden reference, or None.
        pcap_path: Path to the uploaded network capture, or None.

    Returns:
        None. Results are written to the database and streamed over the
        scan's SSE queue as a side effect.

    Raises:
        None. All failures are caught, logged, and recorded via
        `database.fail_scan()` -- this function is the target of a
        `threading.Thread` and has no caller to propagate an exception to.
    """
    try:
        database.update_scan_status(scan_id, "running")
        all_findings: List[Finding] = []
        modules_run = ["firmware_pipeline", "firmware_pipeline_extracted", "filesystem", "yara_engine", "strings"]

        _emit(scan_id, "Extracting firmware with Binwalk...", 10)
        pipeline_started_at = time.time()
        all_findings.extend(_safe_run("firmware_pipeline", firmware_pipeline.run_pipeline, str(firmware_path)))

        # firmware_pipeline.run_pipeline() runs Binwalk extraction, entropy
        # analysis, and filesystem checks in one call (see its own module
        # docstring) -- these two steps report on work already done above,
        # since there's no way to get finer-grained progress out of that
        # call without modifying it.
        _emit(scan_id, "Running entropy analysis...", 25)
        _emit(scan_id, "Running YARA signature matching...", 40)
        yara_findings: List[Finding] = []
        try:
            engine = yara_engine.YaraEngine(str(_YARA_RULES_DIR)).compile()
            if golden_path is not None:
                engine.learn_baseline([str(golden_path)])
            raw_yara_findings = engine.scan_file(firmware_path)
            yara_findings = [
                _yara_finding_to_core(f) for f in raw_yara_findings if not f.suppressed_by_baseline
            ]
        except Exception:
            logger.exception("yara_engine failed; continuing with the rest of the pipeline")
        all_findings.extend(yara_findings)

        _emit(scan_id, "Running filesystem anomaly detection...", 55)

        _emit(scan_id, "Running string analysis...", 65)
        all_findings.extend(_safe_run("strings", strings.analyze, str(firmware_path)))

        if golden_path is not None:
            _emit(scan_id, "Running golden-image diff...", 75)
            all_findings.extend(
                _safe_run("golden_diff", golden_diff.analyze_diff, str(golden_path), str(firmware_path))
            )
            modules_run.append("golden_diff")

        if pcap_path is not None:
            _emit(scan_id, "Analysing network capture...", 85)
            all_findings.extend(_safe_run("network_monitor", network_monitor.analyze, str(pcap_path)))
            modules_run.append("network_monitor")

        _emit(scan_id, "Computing final score...", 90)
        scan_score = score_findings(all_findings, modules_run=modules_run)

        _emit(scan_id, "Generating report...", 95)
        entropy_plot_path = _locate_entropy_plot(firmware_path, pipeline_started_at)

        findings_json = json.dumps([asdict(f) for f in all_findings])
        score_json = json.dumps(asdict(scan_score))

        database.complete_scan(
            scan_id, scan_score.verdict, scan_score.total_score, findings_json, score_json, entropy_plot_path
        )

        _get_queue(scan_id).put(
            {
                "step": "Complete",
                "progress": 100,
                "complete": True,
                "verdict": scan_score.verdict,
                "score": scan_score.total_score,
            }
        )
    except Exception as exc:
        logger.exception("Scan %s failed", scan_id)
        database.fail_scan(scan_id, str(exc))
        _get_queue(scan_id).put(
            {"step": "Failed", "progress": 100, "complete": True, "error": str(exc)}
        )
    finally:
        scan_upload_dir = config.WEB_UPLOAD_FOLDER / scan_id
        shutil.rmtree(scan_upload_dir, ignore_errors=True)


@app.route("/")
def landing():
    """Render the product landing page."""
    return render_template("landing.html", active_page="home")


@app.route("/dashboard")
def dashboard():
    """Render the scan dashboard: upload form + scan history."""
    return render_template("index.html", active_page="dashboard")


@app.route("/about")
def about():
    """Render the about/team page."""
    return render_template("about.html", active_page="about")


@app.route("/compare")
def compare():
    """Render a side-by-side comparison of two scans (?a=<id>&b=<id>)."""
    scan_a_id = request.args.get("a")
    scan_b_id = request.args.get("b")
    if not scan_a_id or not scan_b_id:
        abort(400)
    if database.get_scan(scan_a_id) is None or database.get_scan(scan_b_id) is None:
        abort(404)
    return render_template(
        "compare.html", active_page="dashboard", scan_a_id=scan_a_id, scan_b_id=scan_b_id
    )


@app.route("/scan", methods=["POST"])
def start_scan():
    """Accept a firmware upload (plus optional golden/pcap) and start a scan.

    Returns:
        JSON `{"scan_id": ..., "redirect": "/scan/<id>"}` on success, or
        a 400 JSON error if no firmware file was provided.
    """
    firmware_file = request.files.get("firmware")
    if firmware_file is None or firmware_file.filename == "":
        return jsonify({"error": "A firmware file is required."}), 400

    golden_file = request.files.get("golden")
    pcap_file = request.files.get("pcap")

    scan_id = str(uuid.uuid4())
    scan_dir = config.WEB_UPLOAD_FOLDER / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    firmware_filename = secure_filename(firmware_file.filename)
    firmware_path = scan_dir / firmware_filename
    firmware_file.save(firmware_path)

    golden_path: Optional[Path] = None
    if golden_file is not None and golden_file.filename:
        golden_path = scan_dir / secure_filename(golden_file.filename)
        golden_file.save(golden_path)

    pcap_path: Optional[Path] = None
    if pcap_file is not None and pcap_file.filename:
        pcap_path = scan_dir / secure_filename(pcap_file.filename)
        pcap_file.save(pcap_path)

    database.create_scan(
        scan_id,
        firmware_filename,
        firmware_path.stat().st_size,
        has_golden=golden_path is not None,
        has_pcap=pcap_path is not None,
    )

    thread = threading.Thread(
        target=run_pipeline_for_scan,
        args=(scan_id, firmware_path, golden_path, pcap_path),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "redirect": f"/scan/{scan_id}"})


@app.route("/scan/<scan_id>")
def scan_detail(scan_id: str):
    """Serve the scan detail/report page."""
    scan = database.get_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("report.html", scan_id=scan_id, scan=scan, active_page="dashboard")


@app.route("/scan/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    """Delete a scan record and its uploaded files.

    The DB write uses an inline sqlite3 connection rather than a
    `web/database.py` helper because this change is scoped to
    `web/app.py`; it mirrors `database._connect()`'s parameters.

    Returns:
        JSON `{"deleted": true}`, or 404 if no such scan exists.
    """
    if database.get_scan(scan_id) is None:
        abort(404)
    with sqlite3.connect(str(config.WEB_DATABASE_PATH), timeout=10) as connection:
        connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    shutil.rmtree(config.WEB_UPLOAD_FOLDER / scan_id, ignore_errors=True)
    return jsonify({"deleted": True})


@app.route("/scan/<scan_id>/stream")
def scan_stream(scan_id: str):
    """Server-Sent Events endpoint streaming a scan's progress.

    A scan already complete/errored at connect time (e.g. the report
    page was reloaded after the pipeline finished) gets one synthesized
    terminal event built from the database row instead of waiting on the
    (possibly already-drained) in-memory queue.
    """
    scan = database.get_scan(scan_id)
    if scan is None:
        abort(404)

    def generate():
        if scan["status"] in ("complete", "error"):
            if scan["status"] == "complete":
                terminal = {
                    "step": "Complete",
                    "progress": 100,
                    "complete": True,
                    "verdict": scan["verdict"],
                    "score": scan["total_score"],
                }
            else:
                terminal = {
                    "step": "Failed",
                    "progress": 100,
                    "complete": True,
                    "error": scan["error_message"],
                }
            yield _sse_format(terminal)
            return

        event_queue = _get_queue(scan_id)
        while True:
            event = event_queue.get()
            yield _sse_format(event)
            if event.get("complete"):
                break

    response = Response(stream_with_context(generate()), mimetype="text/event-stream")
    response.headers["Cache-Control"] = "no-cache"
    response.headers["X-Accel-Buffering"] = "no"
    return response


@app.route("/scan/<scan_id>/report")
def scan_report(scan_id: str):
    """Return a scan's full findings/score as JSON."""
    scan = database.get_scan(scan_id)
    if scan is None:
        abort(404)

    report = dict(scan)
    report["findings"] = json.loads(scan["findings_json"]) if scan["findings_json"] else []
    report["score"] = json.loads(scan["score_json"]) if scan["score_json"] else None
    del report["findings_json"]
    del report["score_json"]
    return jsonify(report)


@app.route("/scan/<scan_id>/plot")
def scan_plot(scan_id: str):
    """Serve a scan's saved entropy plot PNG.

    `entropy_plot_path` in the database is a server-side filesystem
    path (not itself a URL), so the frontend's <img> tag points here
    instead.
    """
    scan = database.get_scan(scan_id)
    if scan is None or not scan.get("entropy_plot_path"):
        abort(404)
    plot_path = Path(scan["entropy_plot_path"])
    if not plot_path.is_file():
        abort(404)
    return send_file(plot_path, mimetype="image/png")


@app.route("/history")
def history():
    """Return recent scans as JSON for the dashboard's history panel."""
    scans = database.list_scans(limit=20)
    for scan in scans:
        scan.pop("findings_json", None)
        scan.pop("score_json", None)
    return jsonify(scans)


@app.errorhandler(413)
def too_large(_error):
    """Clean JSON response for an oversized upload."""
    return (
        jsonify({"error": f"Upload exceeds the {config.WEB_MAX_FIRMWARE_SIZE_MB}MB limit."}),
        413,
    )


def _init_app() -> None:
    """Ensure the upload folder and database exist before serving requests."""
    config.WEB_UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
    database.init_db()


_init_app()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=config.LOG_FORMAT)
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False, threaded=True)
