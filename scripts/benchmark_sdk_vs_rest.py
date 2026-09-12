"""Benchmark comparing REST API latency vs. In-Process SDK execution latency.

Executes prompt security evaluation across both delivery modes and calculates
P50, P95, and P99 latency percentiles.
"""

from __future__ import annotations

from pathlib import Path
import statistics
import sys
import time

# Ensure project root is in python path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from app.bootstrap import create_app
from sdk import AISecurityClient, Profile


def run_benchmark(iterations: int = 500) -> None:
    print("\n" + "=" * 65)
    print("  AI SECURITY CONTROL PLANE: SDK vs REST LATENCY BENCHMARK")
    print(f"  Iterations: {iterations} evaluations per mode")
    print("=" * 65)

    test_prompt = "Hello, can you help me structure my project documentation?"

    # 1. Benchmark In-Process Embedded SDK
    sdk_client = AISecurityClient(Profile.LITE)
    sdk_latencies_ms: list[float] = []

    # Warmup
    for _ in range(20):
        sdk_client.scan_prompt(test_prompt)

    t0 = time.perf_counter()
    for _ in range(iterations):
        start = time.perf_counter()
        sdk_client.scan_prompt(test_prompt)
        sdk_latencies_ms.append((time.perf_counter() - start) * 1000)
    sdk_total_time = time.perf_counter() - t0

    # 2. Benchmark FastAPI REST API
    app = create_app()
    test_client = TestClient(app)
    rest_latencies_ms: list[float] = []
    payload = {"prompt": test_prompt}

    # Warmup
    for _ in range(20):
        test_client.post("/v1/security/prompt/scan", json=payload)

    t0 = time.perf_counter()
    for _ in range(iterations):
        start = time.perf_counter()
        resp = test_client.post("/v1/security/prompt/scan", json=payload)
        assert resp.status_code == 200
        rest_latencies_ms.append((time.perf_counter() - start) * 1000)
    rest_total_time = time.perf_counter() - t0

    # Statistics Calculation
    def calc_stats(latencies: list[float]) -> dict[str, float]:
        sorted_lats = sorted(latencies)
        n = len(sorted_lats)
        p50 = sorted_lats[int(n * 0.50)]
        p95 = sorted_lats[int(n * 0.95)]
        p99 = sorted_lats[int(n * 0.99)]
        avg = statistics.mean(sorted_lats)
        return {"avg": avg, "p50": p50, "p95": p95, "p99": p99}

    sdk_stats = calc_stats(sdk_latencies_ms)
    rest_stats = calc_stats(rest_latencies_ms)

    speedup = rest_stats["avg"] / sdk_stats["avg"] if sdk_stats["avg"] > 0 else 1.0

    print("-" * 65)
    print(f" {'METRIC':<18} | {'IN-PROCESS SDK':<18} | {'REST API':<18}")
    print("-" * 65)
    print(f" {'P50 Latency':<18} | {sdk_stats['p50']:.3f} ms            | {rest_stats['p50']:.3f} ms")
    print(f" {'P95 Latency':<18} | {sdk_stats['p95']:.3f} ms            | {rest_stats['p95']:.3f} ms")
    print(f" {'P99 Latency':<18} | {sdk_stats['p99']:.3f} ms            | {rest_stats['p99']:.3f} ms")
    print(f" {'Average Latency':<18} | {sdk_stats['avg']:.3f} ms            | {rest_stats['avg']:.3f} ms")
    print(f" {'Throughput':<18} | {iterations / sdk_total_time:.1f} req/s       | {iterations / rest_total_time:.1f} req/s")
    print("-" * 65)
    print(f" [RESULT] In-Process SDK is {speedup:.1f}x faster than REST API.")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_benchmark(500)
