from __future__ import annotations

import argparse

from evaluation.evidence import (
    LatencyThresholds,
    build_evidence,
    safe_console_summary,
    write_evidence,
)
from evaluation.matrix import run_default_fault_matrix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Phase 11 fault matrix")
    parser.add_argument(
        "--evidence",
        default=".artifacts/phase11/resilience-evidence.json",
        help="path for the sanitized evidence artifact",
    )
    parser.add_argument("--p95-limit-ms", type=int, default=250)
    parser.add_argument("--max-limit-ms", type=int, default=500)
    arguments = parser.parse_args(argv)
    thresholds = LatencyThresholds(
        p95_duration_ms=arguments.p95_limit_ms,
        max_duration_ms=arguments.max_limit_ms,
    )
    evidence = build_evidence(run_default_fault_matrix(), thresholds)
    write_evidence(evidence, arguments.evidence)
    print(safe_console_summary(evidence))
    return 0 if evidence.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
