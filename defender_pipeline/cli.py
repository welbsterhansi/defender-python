"""CLI dispatch — argparse-based subcommand router.

Subcommands (stubbed in P0.4; filled in by later tasks):

    scan     — Report-only ACR scan (P0.5)
    cluster  — OpenShift cross-reference (P0.6)
    expand   — Grouped CSV → per-CVE rows (P0.7)
    report   — HTML report generation   (P0.7)
    all      — scan → cluster → expand → report (P0.7)
    diff     — Byte-diff bash vs Python outputs (P0.5+, dev aid)

Each unimplemented subcommand exits with code 2 and a clear pointer to
the task that will implement it. This lets ``--help`` and the CLI shape
be exercised in tests before any real logic lands.
"""
from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from defender_pipeline import __version__

# ---------------------------------------------------------------------------
# Exit codes (public contract — mirrors defender.sh / check_ocp.sh)
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_IMPLEMENTED = 2   # stubbed subcommand
EXIT_PARTIAL_COVERAGE = 3  # matches check_ocp.sh contract (task P0.6)


def _not_yet_implemented(subcommand: str, task_id: str) -> NoReturn:
    """Bail out of a stubbed subcommand with a pointer to the task that
    will implement it."""
    print(
        f"error: subcommand `{subcommand}` is not yet implemented. "
        f"Tracking: task {task_id} (see docs/python-architecture.md).",
        file=sys.stderr,
    )
    sys.exit(EXIT_NOT_IMPLEMENTED)


# ---------------------------------------------------------------------------
# Subcommand handlers — stubs at P0.4. Signatures kept realistic so the
# tests can exercise --help and the eventual implementers only fill in
# the body.
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    """Report-only ACR scan — Python API-first (P0.5).

    Uses Azure SDK directly (no `az`/`az rest`/subprocess). Same output
    as ``defender.sh`` in report-only mode: 19-column CSV at
    ``args.output``.
    """
    from pathlib import Path

    from defender_pipeline.config import from_env
    from defender_pipeline.findings.scan import ScanOptions, run_scan
    from defender_pipeline.logging_setup import setup

    setup(log_format=args.log_format, level=args.log_level)

    scan_repository, scan_digest = _parse_scan_image_ref(args.scan_image)

    repositories: list[str] | None = None
    if args.repositories:
        repositories = [r.strip() for r in args.repositories.split(",") if r.strip()]

    opts = ScanOptions(
        acr_name=args.acr_name,
        min_score=args.min_score,
        max_score=args.max_score,
        repository=args.repository,
        repositories=repositories,
        scan_repository=scan_repository,
        scan_digest=scan_digest,
        skip_tags=args.skip_tags,
        output=Path(args.output),
    )

    config = from_env()
    if args.parallelism != 8:
        # CLI override wins over env.
        from dataclasses import replace
        config = replace(config, max_workers=args.parallelism)

    try:
        rows = run_scan(opts, config=config)
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"scan complete: {rows} rows written to {args.output}", file=sys.stderr)
    return EXIT_OK


def _parse_scan_image_ref(ref: str | None) -> tuple[str | None, str | None]:
    """Parse a `--scan-image` value into (repository, digest).

    Formats accepted:
      * ``repo``                     → (repo, None)
      * ``repo:tag``                 → (repo, None) — tag ignored at scan-time
      * ``repo@sha256:<hex>``        → (repo, "sha256:<hex>")
    """
    if not ref:
        return None, None
    if "@" in ref:
        repo, digest = ref.split("@", 1)
        return repo, digest
    if ":" in ref:
        repo, _tag = ref.split(":", 1)
        return repo, None
    return ref, None


def cmd_cluster(args: argparse.Namespace) -> int:
    """OpenShift cross-reference — Python API-first (P0.6).

    Uses the kubernetes Python client directly (no ``oc`` subprocess).
    Same output as ``check_ocp.sh``: 24-column CSV at ``args.output``.
    Exit code follows the frozen coverage contract (0 COMPLETE, 3 PARTIAL).
    """
    from pathlib import Path

    from defender_pipeline.logging_setup import setup
    from defender_pipeline.openshift.cluster import ClusterOptions, run_cluster

    setup(log_format=args.log_format, level=args.log_level)

    opts = ClusterOptions(
        vulnerabilities=Path(args.vulnerabilities),
        output=Path(args.output),
        kubeconfig=Path(args.kubeconfig) if args.kubeconfig else None,
    )

    try:
        return run_cluster(opts)
    except Exception as exc:
        print(f"cluster failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR


def cmd_expand(args: argparse.Namespace) -> int:
    """Grouped CSV → per-CVE row explosion (P0.7a).

    Same output as ``expandcsv.py``: 22-column CSV at ``args.output``.
    """
    from pathlib import Path

    from defender_pipeline.logging_setup import setup
    from defender_pipeline.reports.expand import ExpandOptions, run_expand

    setup(log_format=args.log_format, level=args.log_level)

    opts = ExpandOptions(
        cruzamento=Path(args.cruzamento),
        vulnerabilities=Path(args.vulnerabilities),
        output=Path(args.output),
    )

    try:
        rows = run_expand(opts)
    except Exception as exc:
        print(f"expand failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(f"expand complete: {rows} rows written to {args.output}", file=sys.stderr)
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    """HTML report generation. Implemented in P0.7."""
    _not_yet_implemented("report", "P0.7")


def cmd_all(args: argparse.Namespace) -> int:
    """Full pipeline: scan → cluster → expand → report. Implemented in P0.7."""
    _not_yet_implemented("all", "P0.7")


def cmd_diff(args: argparse.Namespace) -> int:
    """Byte-diff bash pipeline vs Python pipeline for validation (P0.5).

    Reads both CSVs, compares header + row content. Exit 0 = identical,
    1 = differences found. Prints a short summary to stderr and (on
    diff) the first N differing lines with a hint.
    """
    from pathlib import Path

    bash_csv = Path(args.bash_csv)
    py_csv = Path(args.python_csv)

    if not bash_csv.exists():
        print(f"error: bash CSV not found: {bash_csv}", file=sys.stderr)
        return EXIT_ERROR
    if not py_csv.exists():
        print(f"error: python CSV not found: {py_csv}", file=sys.stderr)
        return EXIT_ERROR

    bash_lines = bash_csv.read_text(encoding="utf-8").splitlines()
    py_lines = py_csv.read_text(encoding="utf-8").splitlines()

    if bash_lines == py_lines:
        print(
            f"diff: identical ({len(bash_lines)} lines) — {bash_csv} == {py_csv}",
            file=sys.stderr,
        )
        return EXIT_OK

    # Report differences.
    print(
        f"diff: bash={len(bash_lines)} lines, python={len(py_lines)} lines",
        file=sys.stderr,
    )

    # Header
    if bash_lines and py_lines and bash_lines[0] != py_lines[0]:
        print("DIFF (header):", file=sys.stderr)
        print(f"  - bash:   {bash_lines[0]}", file=sys.stderr)
        print(f"  - python: {py_lines[0]}", file=sys.stderr)

    # First 5 differing rows
    diff_count = 0
    for i, (a, b) in enumerate(zip(bash_lines, py_lines, strict=False)):
        if a != b:
            diff_count += 1
            if diff_count <= 5:
                print(f"DIFF (line {i + 1}):", file=sys.stderr)
                print(f"  - bash:   {a}", file=sys.stderr)
                print(f"  - python: {b}", file=sys.stderr)

    remaining = abs(len(bash_lines) - len(py_lines))
    total = diff_count + remaining
    print(
        f"diff: {total} differing/missing line(s); "
        f"{'CSVs differ' if total else 'CSVs identical'}",
        file=sys.stderr,
    )
    return EXIT_ERROR if total else EXIT_OK


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defender_pipeline",
        description=(
            "Python API-first pipeline: ACR vulnerability scan via Azure SDKs "
            "+ OpenShift cross-reference via Kubernetes Python client + HTML "
            "report. Parallel to (and eventually replacing) the bash pipeline."
        ),
        epilog=(
            "See docs/python-architecture.md for design and "
            "docs/contracts/ for the output contracts this CLI preserves."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"defender_pipeline {__version__}",
    )

    # Global options shared by all subcommands
    parser.add_argument(
        "--parallelism", type=int, default=8, metavar="N",
        help="Max concurrent SDK calls (default: 8; stays under Azure ARG "
             "rate limit of ~15 QPS per identity).",
    )
    parser.add_argument(
        "--log-format", choices=["text", "json"], default="text",
        help="Output log format (default: text — matches defender.sh audit "
             "trail line shape).",
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )

    subs = parser.add_subparsers(dest="command", metavar="SUBCOMMAND", required=True)

    # scan --------------------------------------------------------------
    p_scan = subs.add_parser(
        "scan",
        help="Report-only ACR scan (batched two-phase via Azure SDKs).",
        description="Equivalent of `defender.sh` in report-only mode.",
    )
    p_scan.add_argument("--acr-name", required=True, metavar="NAME")
    p_scan.add_argument("--min-score", type=float, default=9.0)
    p_scan.add_argument("--max-score", type=float, default=10.0)
    scope = p_scan.add_mutually_exclusive_group()
    scope.add_argument("--repository", metavar="SUBSTRING",
                       help="Broad substring filter (contains semantics).")
    scope.add_argument("--repositories", metavar="a,b,c",
                       help="Controlled exact list of repo names.")
    scope.add_argument("--scan-image", metavar="REF",
                       help="Scan a specific repo, tag, or digest.")
    p_scan.add_argument("--skip-tags", action="store_true",
                        help="Skip Phase 1 tag_resolve; all rows get tag=N/A.")
    p_scan.add_argument("--output", default="vulnerable_images_report.csv",
                        metavar="PATH")
    p_scan.set_defaults(func=cmd_scan)

    # cluster -----------------------------------------------------------
    p_cluster = subs.add_parser(
        "cluster",
        help="OpenShift cross-reference (workloads × CVE CSV).",
        description="Equivalent of `check_ocp.sh`. Exits 3 on partial coverage.",
    )
    p_cluster.add_argument("--vulnerabilities", default="vulnerable_images_report.csv",
                           metavar="PATH")
    p_cluster.add_argument("--output", default="resultado_cruzamento.csv",
                           metavar="PATH")
    p_cluster.add_argument("--kubeconfig", metavar="PATH",
                           help="Override KUBECONFIG env / default location.")
    p_cluster.set_defaults(func=cmd_cluster)

    # expand ------------------------------------------------------------
    p_expand = subs.add_parser(
        "expand",
        help="Explode grouped rows into one row per CVE.",
        description="Equivalent of `expandcsv.py`.",
    )
    p_expand.add_argument("--cruzamento", default="resultado_cruzamento.csv",
                          metavar="PATH")
    p_expand.add_argument("--vulnerabilities", default="vulnerable_images_report.csv",
                          metavar="PATH")
    p_expand.add_argument("--output", default="expanded.csv", metavar="PATH")
    p_expand.set_defaults(func=cmd_expand)

    # report ------------------------------------------------------------
    p_report = subs.add_parser(
        "report",
        help="Render the single-file HTML report.",
        description="Equivalent of `report.py`.",
    )
    p_report.add_argument("--input", default="expanded.csv", metavar="PATH")
    p_report.add_argument("--output", default="vulnerability_report.html",
                          metavar="PATH")
    p_report.set_defaults(func=cmd_report)

    # all ---------------------------------------------------------------
    p_all = subs.add_parser(
        "all",
        help="Run the full pipeline: scan → cluster → expand → report.",
    )
    # Reuses scan's --acr-name; other flags accept the same defaults.
    p_all.add_argument("--acr-name", required=True, metavar="NAME")
    p_all.add_argument("--min-score", type=float, default=9.0)
    p_all.add_argument("--max-score", type=float, default=10.0)
    p_all.add_argument("--skip-tags", action="store_true")
    p_all.set_defaults(func=cmd_all)

    # diff --------------------------------------------------------------
    p_diff = subs.add_parser(
        "diff",
        help="Compare bash pipeline output vs Python pipeline output (dev aid).",
    )
    p_diff.add_argument("--bash-csv", required=True, metavar="PATH")
    p_diff.add_argument("--python-csv", required=True, metavar="PATH")
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
