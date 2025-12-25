import argparse
import hashlib
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Event

from core.hash_handler import crack_chunk, init_worker


def build_candidates(total, password):
    candidates = [f"word{i}".encode("utf-8") for i in range(total - 1)]
    candidates.append(password.encode("utf-8"))
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Kracker Barrel benchmark harness")
    parser.add_argument("--batch-size", type=int, default=2000)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--candidates", type=int, default=10000)
    args = parser.parse_args()

    password = "benchpass"
    md5_hex = hashlib.md5(password.encode("utf-8")).hexdigest()
    target_hashes = [f"$md5${md5_hex}"]
    hash_type = "md5"

    candidates = build_candidates(args.candidates, password)
    batches = [candidates[i:i + args.batch_size] for i in range(0, len(candidates), args.batch_size)]
    stop_event = Event()

    start = time.perf_counter()
    total_verified = 0
    with ProcessPoolExecutor(
        max_workers=args.workers,
        initializer=init_worker,
        initargs=(hash_type, target_hashes, stop_event),
    ) as executor:
        futures = [
            executor.submit(crack_chunk, batch)
            for batch in batches
        ]
        for future in as_completed(futures):
            _, chunk_count = future.result()
            total_verified += chunk_count
    elapsed = time.perf_counter() - start
    rate = total_verified / elapsed if elapsed else 0

    print(f"Candidates verified: {total_verified}")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Candidates/sec: {rate:.1f}")


if __name__ == "__main__":
    main()
