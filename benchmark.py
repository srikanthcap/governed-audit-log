"""
benchmark.py — Performance Benchmarks for Governed Audit Log

Measures throughput and latency of the core subsystems:
  1. PII Redaction (regex-only and spaCy NER if available)
  2. SHA-256 tamper-detection hashing (compute & verify)
  3. Password hashing  (PBKDF2-HMAC-SHA256) and verification
  4. Fernet AES-256 encryption and decryption
  5. Retention expiry calculation

Run:
    python benchmark.py
    python benchmark.py --iterations 500
    python benchmark.py --output results.json
"""

import argparse
import json
import statistics
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List

# ─── Fixtures ─────────────────────────────────────────────────────────────────

SHORT_TEXT = "Hello, my name is John Doe."

MEDIUM_TEXT = (
    "User alice@example.com called from 192.168.1.42 and provided SSN 123-45-6789. "
    "Her credit card number is 4111-1111-1111-1111 and her phone is +1 (555) 867-5309. "
    "She also shared API key REDACTED_API_KEY_SAMPLE_abcdefghijklmnopqrs for service access."
)

LONG_TEXT = (
    "Audit entry for session {uid}. "
    "Agent contacted user john.smith@corp.example.com (IP: 10.0.0.{n}) "
    "who submitted SSN 987-65-{n:04d} and card 5500-0000-0000-{n:04d}. "
    "API credential pk_test_{uid} was rotated. "
    "Location: New York. Organisation: Acme Corp. "
    "Phone: +44 20 7946 {n:04d}. "
).format(uid=uuid.uuid4().hex[:16], n=1234)

SAMPLE_PASSWORD = "S3cur3P@ssw0rd!"

# ─── Benchmark runner ─────────────────────────────────────────────────────────

def run_benchmark(
    label: str,
    fn: Callable,
    iterations: int,
    warmup: int = 3,
) -> Dict:
    """Run *fn* for *iterations* times and collect timing statistics."""
    # Warmup
    for _ in range(warmup):
        fn()

    latencies_ms: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1_000)

    total_ms   = sum(latencies_ms)
    mean_ms    = statistics.mean(latencies_ms)
    median_ms  = statistics.median(latencies_ms)
    stdev_ms   = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0.0
    p95_ms     = sorted(latencies_ms)[int(0.95 * len(latencies_ms)) - 1]
    p99_ms     = sorted(latencies_ms)[int(0.99 * len(latencies_ms)) - 1]
    throughput  = 1_000 / mean_ms if mean_ms > 0 else float("inf")

    return {
        "label":          label,
        "iterations":     iterations,
        "total_ms":       round(total_ms,   3),
        "mean_ms":        round(mean_ms,    4),
        "median_ms":      round(median_ms,  4),
        "stdev_ms":       round(stdev_ms,   4),
        "p95_ms":         round(p95_ms,     4),
        "p99_ms":         round(p99_ms,     4),
        "throughput_ops": round(throughput, 2),
    }


def print_result(r: Dict) -> None:
    bar = "-" * 68
    print(f"\n{bar}")
    print(f"  {r['label']}")
    print(bar)
    print(f"  Iterations : {r['iterations']}")
    print(f"  Mean       : {r['mean_ms']:.4f} ms")
    print(f"  Median     : {r['median_ms']:.4f} ms")
    print(f"  Std-Dev    : {r['stdev_ms']:.4f} ms")
    print(f"  P95        : {r['p95_ms']:.4f} ms")
    print(f"  P99        : {r['p99_ms']:.4f} ms")
    print(f"  Throughput : {r['throughput_ops']:.2f} ops/sec")


# ─── Individual benchmarks ────────────────────────────────────────────────────

def bench_redaction(iterations: int) -> List[Dict]:
    from redaction import redact_text

    results = []
    user_id = str(uuid.uuid4())

    results.append(run_benchmark(
        "PII Redaction — short text (~27 chars)",
        lambda: redact_text(SHORT_TEXT, user_id),
        iterations,
    ))

    results.append(run_benchmark(
        "PII Redaction — medium text (~350 chars, 6 PII entities)",
        lambda: redact_text(MEDIUM_TEXT, user_id),
        iterations,
    ))

    results.append(run_benchmark(
        "PII Redaction — long text (~500 chars, multiple entities)",
        lambda: redact_text(LONG_TEXT, user_id),
        iterations,
    ))

    return results


def bench_hashing(iterations: int) -> List[Dict]:
    from security import compute_record_hash, verify_record_hash
    from models import AuditRecord

    ts = datetime.now(timezone.utc)
    prompt   = MEDIUM_TEXT
    response = "Processed successfully."
    agent_id = "benchmark-agent"
    user_id  = str(uuid.uuid4())

    # Pre-compute hash for verify benchmark
    record_hash = compute_record_hash(prompt, response, agent_id, user_id, ts)
    record = AuditRecord(
        prompt_redacted=prompt,
        response_redacted=response,
        agent_id=agent_id,
        user_id=user_id,
        timestamp=ts,
        retention_category="GENERAL",
        retention_expires_at=ts,
        record_hash=record_hash,
    )

    results = []

    results.append(run_benchmark(
        "SHA-256 Hash — compute_record_hash",
        lambda: compute_record_hash(prompt, response, agent_id, user_id, ts),
        iterations,
    ))

    results.append(run_benchmark(
        "SHA-256 Hash — verify_record_hash",
        lambda: verify_record_hash(record),
        iterations,
    ))

    return results


def bench_password(iterations: int) -> List[Dict]:
    from security import hash_password, verify_password

    # Use fewer iterations for password hashing — it's intentionally slow
    pwd_iters = min(iterations, 20)

    stored = hash_password(SAMPLE_PASSWORD)

    results = []

    results.append(run_benchmark(
        "Password — hash_password (PBKDF2-SHA256, 100k rounds)",
        lambda: hash_password(SAMPLE_PASSWORD),
        pwd_iters,
        warmup=1,
    ))

    results.append(run_benchmark(
        "Password — verify_password",
        lambda: verify_password(SAMPLE_PASSWORD, stored),
        pwd_iters,
        warmup=1,
    ))

    return results


def bench_encryption(iterations: int) -> List[Dict]:
    from redaction import encrypt_value, decrypt_value

    sample_pii = "john.doe@example.com"
    ciphertext = encrypt_value(sample_pii)

    results = []

    results.append(run_benchmark(
        "Fernet AES-256 — encrypt_value",
        lambda: encrypt_value(sample_pii),
        iterations,
    ))

    results.append(run_benchmark(
        "Fernet AES-256 — decrypt_value",
        lambda: decrypt_value(ciphertext),
        iterations,
    ))

    return results


def bench_retention(iterations: int) -> List[Dict]:
    from retention import RETENTION_DAYS_MAP
    from datetime import timedelta

    ts = datetime.now(timezone.utc)

    results = []

    for category in ("GENERAL", "FINANCIAL", "HEALTHCARE"):
        days = RETENTION_DAYS_MAP[category]
        results.append(run_benchmark(
            f"Retention — expiry calculation ({category}, {days}d)",
            lambda d=days: ts + timedelta(days=d),
            iterations,
        ))

    return results


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Performance benchmarks for Governed Audit Log"
    )
    parser.add_argument(
        "--iterations", "-n",
        type=int,
        default=200,
        help="Number of iterations per benchmark (default: 200). "
             "Password benchmarks are capped at 20 automatically.",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help="Optional path to write JSON results (e.g. results.json).",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        choices=["redaction", "hashing", "password", "encryption", "retention"],
        default=[],
        help="Subsystems to skip.",
    )
    args = parser.parse_args()

    print("=" * 68)
    print("  Governed Audit Log - Performance Benchmarks")
    print(f"  Timestamp : {datetime.now(timezone.utc).isoformat()}")
    print(f"  Iterations: {args.iterations} (password capped at 20)")
    print("=" * 68)

    all_results: List[Dict] = []

    suite = [
        ("redaction",  bench_redaction),
        ("hashing",    bench_hashing),
        ("password",   bench_password),
        ("encryption", bench_encryption),
        ("retention",  bench_retention),
    ]

    for name, fn in suite:
        if name in args.skip:
            print(f"\n[SKIP] {name}")
            continue
        print(f"\n[RUN]  {name} ...")
        try:
            results = fn(args.iterations)
            for r in results:
                print_result(r)
                all_results.append(r)
        except Exception as exc:
            print(f"  ERROR: {exc}")

    # Summary table
    print("\n" + "=" * 68)
    print(f"  {'Benchmark':<46}  {'Mean (ms)':>10}  {'ops/sec':>8}")
    print("=" * 68)
    for r in all_results:
        label = r["label"][:46]
        print(f"  {label:<46}  {r['mean_ms']:>10.4f}  {r['throughput_ops']:>8.1f}")
    print("=" * 68)
    print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "iterations": args.iterations,
                    "results": all_results,
                },
                f,
                indent=2,
            )
        print(f"\n  Results written to: {args.output}")


if __name__ == "__main__":
    main()
