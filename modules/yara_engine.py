"""
yara_engine.py — HexWarden (SIH1387)
Owner: Tejas

Wraps yara-python for firmware analysis. Two things make this more than a
`yara -r` shell-out:

  1. Baseline suppression. Rules that also fire on the golden image are
     downgraded, not reported. This is the golden-image concept applied to
     signatures instead of bytes, and it is what keeps the demo from drowning
     in BusyBox false positives.

  2. A normalized finding schema, so correlator.py can merge YARA hits with
     entropy peaks, string hits and crypto constants on a common key
     (file path + offset).

Emits findings; does not decide verdicts. Scoring lives in the correlator.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable, Iterator

import yara

log = logging.getLogger("hexwarden.yara")

# Severity -> base score. The correlator may adjust these.
SEVERITY_SCORE = {
    "info": 5,
    "low": 15,
    "medium": 35,
    "high": 65,
    "critical": 90,
}

DEFAULT_TIMEOUT = 60          # seconds per file
DEFAULT_MAX_FILE = 256 << 20  # 256 MB
MAX_MATCH_STRINGS = 12        # cap per rule, keeps reports readable
CONTEXT_BYTES = 32


@dataclass
class MatchedString:
    identifier: str
    offset: int
    preview: str


@dataclass
class Finding:
    """Common schema shared with strings.py / entropy / crypto_constants."""
    source: str = "yara"
    rule: str = ""
    namespace: str = ""
    severity: str = "info"
    score: int = 0
    category: str = ""
    description: str = ""
    file_path: str = ""
    file_sha256: str = ""
    offset: int | None = None
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: list[MatchedString] = field(default_factory=list)
    suppressed_by_baseline: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["strings"] = [asdict(s) for s in self.strings]
        return d


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _preview(data: bytes) -> str:
    """Printable, length-capped preview of matched bytes."""
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:CONTEXT_BYTES])
    return text


class YaraEngine:
    def __init__(
        self,
        rules_dir: str | Path,
        timeout: int = DEFAULT_TIMEOUT,
        max_file_size: int = DEFAULT_MAX_FILE,
        externals: dict | None = None,
    ):
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.max_file_size = max_file_size
        self.externals = externals or {}
        self.rules: yara.Rules | None = None
        self.baseline_rules: set[str] = set()
        self._seen_hashes: set[str] = set()

    # ---------------------------------------------------------------- compile

    def compile(self) -> "YaraEngine":
        """Compile every .yar/.yara under rules_dir, one namespace per file."""
        filepaths = {}
        for p in sorted(self.rules_dir.rglob("*")):
            if p.suffix.lower() in (".yar", ".yara"):
                filepaths[p.stem] = str(p)

        if not filepaths:
            raise FileNotFoundError(f"No rule files found under {self.rules_dir}")

        try:
            self.rules = yara.compile(
                filepaths=filepaths,
                externals=self.externals,
                includes=True,
            )
        except yara.SyntaxError as e:
            raise RuntimeError(f"YARA rule syntax error: {e}") from e

        log.info("Compiled %d rule namespaces from %s", len(filepaths), self.rules_dir)
        return self

    def save_compiled(self, path: str | Path) -> None:
        """Persist compiled rules so the demo doesn't recompile on every run."""
        if self.rules is None:
            raise RuntimeError("compile() first")
        self.rules.save(str(path))

    def load_compiled(self, path: str | Path) -> "YaraEngine":
        self.rules = yara.load(str(path))
        return self

    # --------------------------------------------------------------- baseline

    def learn_baseline(self, golden_paths: Iterable[str | Path]) -> set[str]:
        """
        Scan the known-good firmware. Any rule that fires here is vendor-normal
        for this device family, so we mark it for suppression.

        Call this before scan_tree() when a golden image is available.
        """
        if self.rules is None:
            raise RuntimeError("compile() first")

        for p in golden_paths:
            p = Path(p)
            targets = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
            for f in targets:
                for m in self._raw_match(f):
                    self.baseline_rules.add(m.rule)

        log.info("Baseline suppression set: %d rules", len(self.baseline_rules))
        return self.baseline_rules

    # ------------------------------------------------------------------ scan

    def _raw_match(self, path: Path) -> list:
        try:
            if path.stat().st_size > self.max_file_size:
                log.warning("Skipping oversized file: %s", path)
                return []
            return self.rules.match(filepath=str(path), timeout=self.timeout)
        except yara.TimeoutError:
            log.warning("YARA timeout on %s", path)
        except yara.Error as e:
            log.warning("YARA error on %s: %s", path, e)
        except OSError as e:
            log.warning("Cannot read %s: %s", path, e)
        return []

    def scan_file(self, path: str | Path, digest: str | None = None) -> list[Finding]:
        if self.rules is None:
            raise RuntimeError("compile() first")

        path = Path(path)
        digest = digest or sha256_file(path)
        findings: list[Finding] = []

        for m in self._raw_match(path):
            meta = dict(m.meta)
            severity = str(meta.get("severity", "info")).lower()
            suppressed = m.rule in self.baseline_rules

            matched: list[MatchedString] = []
            for s in m.strings[:MAX_MATCH_STRINGS]:
                for inst in s.instances[:3]:
                    matched.append(
                        MatchedString(
                            identifier=s.identifier,
                            offset=inst.offset,
                            preview=_preview(inst.matched_data),
                        )
                    )

            findings.append(
                Finding(
                    rule=m.rule,
                    namespace=m.namespace,
                    severity=severity,
                    score=0 if suppressed else SEVERITY_SCORE.get(severity, 5),
                    category=str(meta.get("category", "")),
                    description=str(meta.get("description", "")),
                    file_path=str(path),
                    file_sha256=digest,
                    offset=matched[0].offset if matched else None,
                    tags=list(m.tags),
                    meta=meta,
                    strings=matched,
                    suppressed_by_baseline=suppressed,
                )
            )

        return findings

    def scan_bytes(self, data: bytes, label: str = "<memory>") -> list[Finding]:
        """For carved segments handed over by filesystem.py before they hit disk."""
        if self.rules is None:
            raise RuntimeError("compile() first")

        digest = hashlib.sha256(data).hexdigest()
        findings = []
        try:
            matches = self.rules.match(data=data, timeout=self.timeout)
        except yara.Error as e:
            log.warning("YARA error on %s: %s", label, e)
            return []

        for m in matches:
            meta = dict(m.meta)
            severity = str(meta.get("severity", "info")).lower()
            suppressed = m.rule in self.baseline_rules
            findings.append(
                Finding(
                    rule=m.rule,
                    namespace=m.namespace,
                    severity=severity,
                    score=0 if suppressed else SEVERITY_SCORE.get(severity, 5),
                    category=str(meta.get("category", "")),
                    description=str(meta.get("description", "")),
                    file_path=label,
                    file_sha256=digest,
                    offset=m.strings[0].instances[0].offset if m.strings else None,
                    tags=list(m.tags),
                    meta=meta,
                    suppressed_by_baseline=suppressed,
                )
            )
        return findings

    def scan_tree(
        self,
        root: str | Path,
        dedupe: bool = True,
        raw_image: str | Path | None = None,
    ) -> Iterator[Finding]:
        """
        Walk a binwalk extraction directory. Dedupes by content hash — extracted
        rootfs trees are full of hardlink/duplicate copies of the same binary.

        Also always scans the raw source image, if one is given or can be
        inferred from the `<name>.extracted` naming convention used elsewhere
        in this repo. Binwalk only carves out regions it recognizes — bytes
        in inter-partition padding or appended past the end of the original
        image never make it into the extraction tree, and that is exactly
        where a firmware trojan is likely to hide. Skipping the raw image
        here silently blinds the scanner to that class of implant.
        """
        root = Path(root)

        if raw_image is None:
            name = root.name
            if name.endswith(".extracted"):
                candidate = root.parent / name[: -len(".extracted")]
                if candidate.is_file():
                    raw_image = candidate

        if raw_image is not None:
            raw_image = Path(raw_image)
            try:
                digest = sha256_file(raw_image)
            except OSError as e:
                log.warning("Cannot read raw image %s: %s", raw_image, e)
            else:
                if not (dedupe and digest in self._seen_hashes):
                    self._seen_hashes.add(digest)
                    yield from self.scan_file(raw_image, digest=digest)

        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                digest = sha256_file(path)
            except OSError:
                continue
            if dedupe and digest in self._seen_hashes:
                continue
            self._seen_hashes.add(digest)
            yield from self.scan_file(path, digest=digest)

    # --------------------------------------------------------------- summary

    @staticmethod
    def summarize(findings: list[Finding]) -> dict:
        active = [f for f in findings if not f.suppressed_by_baseline]
        by_sev: dict[str, int] = {}
        by_cat: dict[str, int] = {}
        for f in active:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            if f.category:
                by_cat[f.category] = by_cat.get(f.category, 0) + 1
        return {
            "total_findings": len(findings),
            "active_findings": len(active),
            "suppressed_by_baseline": len(findings) - len(active),
            "max_score": max((f.score for f in active), default=0),
            "by_severity": by_sev,
            "by_category": by_cat,
            "files_flagged": len({f.file_path for f in active}),
        }


# ------------------------------------------------------------------- CLI

def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="HexWarden YARA engine")
    ap.add_argument("target", help="File or extracted-firmware directory to scan")
    ap.add_argument("-r", "--rules", default="rules", help="Rules directory")
    ap.add_argument("-g", "--golden", help="Golden image / extraction dir for baseline suppression")
    ap.add_argument("--raw-image", help="Raw firmware image to scan alongside an extraction dir "
                                         "(auto-detected from '<name>.extracted' naming if omitted)")
    ap.add_argument("-o", "--output", help="Write findings as JSON")
    ap.add_argument("--show-suppressed", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    engine = YaraEngine(args.rules).compile()

    if args.golden:
        engine.learn_baseline([args.golden])

    target = Path(args.target)
    if not target.exists():
        log.error("Target does not exist: %s", target)
        return 1

    findings = (
        engine.scan_file(target)
        if target.is_file()
        else list(engine.scan_tree(target, raw_image=args.raw_image))
    )

    visible = findings if args.show_suppressed else [
        f for f in findings if not f.suppressed_by_baseline
    ]
    visible.sort(key=lambda f: f.score, reverse=True)

    for f in visible:
        flag = " [baseline]" if f.suppressed_by_baseline else ""
        loc = f"@0x{f.offset:x}" if f.offset is not None else ""
        print(f"[{f.severity.upper():8}] {f.rule:<45} {Path(f.file_path).name} {loc}{flag}")
        if f.description:
            print(f"           {f.description}")

    summary = YaraEngine.summarize(findings)
    print("\n--- summary ---")
    for k, v in summary.items():
        print(f"{k}: {v}")

    if args.output:
        Path(args.output).write_text(
            json.dumps(
                {"summary": summary, "findings": [f.to_dict() for f in findings]},
                indent=2,
            )
        )
        print(f"\nWrote {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
