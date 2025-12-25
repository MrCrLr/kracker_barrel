import argparse
import hashlib
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Event

from core.hash_handler import crack_chunk, init_worker
from core.hashmaker import HashMaker


def build_candidates(total, password):
    candidates = [f"word{i}".encode("utf-8") for i in range(total - 1)]
    candidates.append(password.encode("utf-8"))
    return candidates


def build_target_hash(hash_type, password):
    if hash_type == "md5":
        md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest()
        return [f"$md5${md5_hex}"]
    if hash_type == "sha256":
        sha_hex = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return [f"$sha256${sha_hex}"]
    if hash_type == "sha512":
        sha_hex = hashlib.sha512(password.encode("utf-8")).hexdigest()
        return [f"$sha512${sha_hex}"]
    if hash_type == "ntlm":
        from Crypto.Hash import MD4

        md4_hash = MD4.new()
        md4_hash.update(password.encode("utf-16le"))
        return [f"$ntlm${md4_hash.digest().hex()}"]

    maker = HashMaker("argon", [password], "bench.txt", test_mode=True, secure_mode=False)
    if hash_type == "argon":
        return maker.compute_argon(**maker.parameters["argon"])
    if hash_type == "bcrypt":
        return maker.compute_bcrypt(**maker.parameters["bcrypt"])
    if hash_type == "scrypt":
        return maker.compute_scrypt(**maker.parameters["scrypt"])
    if hash_type == "pbkdf2":
        return maker.compute_pbkdf2(**maker.parameters["pbkdf2"])
    raise ValueError(f"Unsupported hash type: {hash_type}")


def parse_int_list(value):
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def default_workers(hash_type):
    cpu_count = os.cpu_count() or 1
    expensive_hashes = {"bcrypt", "argon", "scrypt", "pbkdf2"}
    cap = 4 if hash_type in expensive_hashes else 8
    return min(cpu_count, cap)


def default_batch_size(hash_type):
    expensive_hashes = {"bcrypt", "argon", "scrypt", "pbkdf2"}
    return 1000 if hash_type in expensive_hashes else 50000


def run_bench(hash_type, batch_size, workers, candidates_count):
    password = "benchpass"
    target_hashes = build_target_hash(hash_type, password)
    candidates = build_candidates(candidates_count, password)
    batches = [candidates[i:i + batch_size] for i in range(0, len(candidates), batch_size)]
    stop_event = Event()

    start = time.perf_counter()
    total_verified = 0
    with ProcessPoolExecutor(
        max_workers=workers,
        initializer=init_worker,
        initargs=(hash_type, target_hashes, stop_event),
    ) as executor:
        futures = [executor.submit(crack_chunk, batch) for batch in batches]
        for future in as_completed(futures):
            _, chunk_count = future.result()
            total_verified += chunk_count
    elapsed = time.perf_counter() - start
    batches_processed = len(batches)
    avg_batch_time = elapsed / batches_processed if batches_processed else 0
    rate = total_verified / elapsed if elapsed else 0
    overhead_estimate = 0.0

    return {
        "workers": workers,
        "batch_size": batch_size,
        "candidates": total_verified,
        "elapsed": elapsed,
        "rate": rate,
        "avg_batch_time": avg_batch_time,
        "overhead_estimate": overhead_estimate,
    }


def main():
    parser = argparse.ArgumentParser(description="Kracker Barrel benchmark harness")
    parser.add_argument("--hash-type", type=str, default="md5")
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--candidates", type=int, default=10000)
    parser.add_argument("--sweep", action="store_true", default=False)
    parser.add_argument("--workers-list", type=str, default=None)
    parser.add_argument("--batch-sizes", type=str, default=None)
    parser.add_argument("--csv", type=str, default=None)
    args = parser.parse_args()

    hash_type = args.hash_type
    workers = args.workers if args.workers is not None else default_workers(hash_type)
    batch_size = args.batch_size if args.batch_size is not None else default_batch_size(hash_type)

    if args.sweep:
        workers_list = parse_int_list(args.workers_list) if args.workers_list else [workers]
        batch_sizes = parse_int_list(args.batch_sizes) if args.batch_sizes else [batch_size]
        results = []
        best = None

        for w in workers_list:
            for b in batch_sizes:
                result = run_bench(hash_type, b, w, args.candidates)
                results.append(result)
                if best is None or result["rate"] > best["rate"]:
                    best = result
                print(
                    f"workers={w} batch={b} candidates/sec={result['rate']:.1f} "
                    f"elapsed={result['elapsed']:.2f}s avg_batch={result['avg_batch_time']:.4f}s"
                )

        if args.csv:
            import csv

            with open(args.csv, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(
                    csvfile,
                    fieldnames=[
                        "workers",
                        "batch_size",
                        "candidates",
                        "elapsed",
                        "rate",
                        "avg_batch_time",
                        "overhead_estimate",
                    ],
                )
                writer.writeheader()
                writer.writerows(results)

        if best:
            print(
                f"BEST CONFIG: workers={best['workers']} batch={best['batch_size']} "
                f"candidates/sec={best['rate']:.1f}"
            )
        return

    result = run_bench(hash_type, batch_size, workers, args.candidates)
    print(f"Candidates verified: {result['candidates']}")
    print(f"Elapsed: {result['elapsed']:.2f}s")
    print(f"Candidates/sec: {result['rate']:.1f}")


if __name__ == "__main__":
    main()
