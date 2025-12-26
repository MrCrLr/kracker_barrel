import argparse
import hashlib
import os
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Event
from pathlib import Path

from core.hash_handler import crack_range, init_worker_range
from core.hashmaker import HashMaker
from core.brut_gen import get_brute_count
from core.mask_gen import compile_mask_alphabets, get_mask_space_size


def write_wordlist(total, password, mode):
    temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
    wordlist_path = Path(temp_file.name)
    try:
        if mode == "rule":
            temp_file.write("bench\n")
            for i in range(total - 1):
                temp_file.write(f"word{i}\n")
        else:
            for i in range(total - 1):
                temp_file.write(f"word{i}\n")
            temp_file.write(f"{password}\n")
    finally:
        temp_file.close()
    return wordlist_path


def write_rules_file():
    temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8")
    rules_path = Path(temp_file.name)
    try:
        temp_file.write("APPEND pass\n")
    finally:
        temp_file.close()
    return rules_path


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
    cap = 4 if hash_type in expensive_hashes else 6
    return min(cpu_count, cap)


def default_batch_size(hash_type):
    expensive_hashes = {"bcrypt", "argon", "scrypt", "pbkdf2"}
    return 1000 if hash_type in expensive_hashes else 20000


def run_bench(
    hash_type,
    batch_size,
    workers,
    candidates_count,
    mode,
    wordlist_path,
    rules_path,
    brut_settings,
    mask_pattern,
    custom_strings,
    report_rss,
    wordlist_load_mode,
):
    password = "benchpass"
    target_hashes = build_target_hash(hash_type, password)
    if mode == "brut":
        total_space = get_brute_count(brut_settings)
    elif mode == "mask":
        alphabets = compile_mask_alphabets(mask_pattern, custom_strings)
        total_space = get_mask_space_size(alphabets)
    else:
        total_space = candidates_count
    total_space = min(total_space, candidates_count)
    ranges = [(i, min(i + batch_size, total_space)) for i in range(0, total_space, batch_size)]
    stop_event = Event()

    start = time.perf_counter()
    total_verified = 0
    with ProcessPoolExecutor(
        max_workers=workers,
        initializer=init_worker_range,
        initargs=(
            hash_type,
            target_hashes,
            stop_event,
            mode,
            wordlist_path,
            rules_path,
            None,
            None,
            brut_settings,
            mask_pattern,
            custom_strings,
            1024,
            report_rss,
            wordlist_load_mode,
        ),
    ) as executor:
        futures = [executor.submit(crack_range, work_range) for work_range in ranges]
        rss_values = []
        uss_values = []
        for future in as_completed(futures):
            _, meta = future.result()
            total_verified += meta.get("verified_count", 0)
            if report_rss and meta.get("rss_kb") is not None:
                rss_values.append(meta["rss_kb"])
            if report_rss and meta.get("uss_kb") is not None:
                uss_values.append(meta["uss_kb"])
    elapsed = time.perf_counter() - start
    batches_processed = len(ranges)
    avg_batch_time = elapsed / batches_processed if batches_processed else 0
    rate = total_verified / elapsed if elapsed else 0
    overhead_estimate = 0.0

    rss_kb = max(rss_values) if rss_values else None
    uss_kb = max(uss_values) if uss_values else None
    return {
        "workers": workers,
        "batch_size": batch_size,
        "candidates": total_verified,
        "elapsed": elapsed,
        "rate": rate,
        "avg_batch_time": avg_batch_time,
        "overhead_estimate": overhead_estimate,
        "rss_kb": rss_kb,
        "uss_kb": uss_kb,
    }


def main():
    parser = argparse.ArgumentParser(description="Kracker Barrel benchmark harness")
    parser.add_argument("--hash-type", type=str, default="md5")
    parser.add_argument("--mode", type=str, choices=["dict", "rule", "brut", "mask"], default="dict")
    parser.add_argument("--charset", type=str, default="abcdefghijklmnopqrstuvwxyz")
    parser.add_argument("--min", type=int, default=1)
    parser.add_argument("--max", type=int, default=4)
    parser.add_argument("--pattern", type=str, default="?l?l?l")
    parser.add_argument("--custom", type=str, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--workers", type=int, default=None)
    parser.add_argument("--candidates", type=int, default=10000)
    parser.add_argument("--sweep", action="store_true", default=False)
    parser.add_argument("--workers-list", type=str, default=None)
    parser.add_argument("--batch-sizes", type=str, default=None)
    parser.add_argument("--csv", type=str, default=None)
    parser.add_argument("--report-rss", action="store_true", default=False)
    parser.add_argument("--wordlist-load", type=str, choices=["mmap", "list"], default="mmap")
    args = parser.parse_args()

    hash_type = args.hash_type
    workers = args.workers if args.workers is not None else default_workers(hash_type)
    batch_size = args.batch_size if args.batch_size is not None else default_batch_size(hash_type)

    wordlist_path = None
    rules_path = None
    if args.mode in {"dict", "rule"}:
        wordlist_path = write_wordlist(args.candidates, "benchpass", args.mode)
        if args.mode == "rule":
            rules_path = write_rules_file()
        else:
            rules_path = wordlist_path
    brut_settings = {"charset": args.charset, "min": args.min, "max": args.max}

    try:
        if args.sweep:
            workers_list = parse_int_list(args.workers_list) if args.workers_list else [workers]
            batch_sizes = parse_int_list(args.batch_sizes) if args.batch_sizes else [batch_size]
            results = []
            best = None

            for w in workers_list:
                for b in batch_sizes:
                    result = run_bench(
                        hash_type,
                        b,
                        w,
                        args.candidates,
                        args.mode,
                        wordlist_path,
                        rules_path,
                        brut_settings,
                        args.pattern,
                        args.custom,
                        args.report_rss,
                        args.wordlist_load,
                    )
                    results.append(result)
                    if best is None or result["rate"] > best["rate"]:
                        best = result
                    rss_suffix = ""
                    if args.report_rss:
                        parts = []
                        if result.get("rss_kb") is not None:
                            parts.append(f"rss_kb={result['rss_kb']}")
                        if result.get("uss_kb") is not None:
                            parts.append(f"uss_kb={result['uss_kb']}")
                        if parts:
                            rss_suffix = " " + " ".join(parts)
                    print(
                        f"workers={w} batch={b} candidates/sec={result['rate']:.1f} "
                        f"elapsed={result['elapsed']:.2f}s avg_batch={result['avg_batch_time']:.4f}s{rss_suffix}"
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
                        "rss_kb",
                        "uss_kb",
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

        result = run_bench(
            hash_type,
            batch_size,
            workers,
            args.candidates,
            args.mode,
            wordlist_path,
            rules_path,
            brut_settings,
            args.pattern,
            args.custom,
            args.report_rss,
            args.wordlist_load,
        )
        print(f"Candidates verified: {result['candidates']}")
        print(f"Elapsed: {result['elapsed']:.2f}s")
        print(f"Candidates/sec: {result['rate']:.1f}")
        if args.report_rss:
            if result.get("rss_kb") is not None:
                print(f"Max RSS (KB): {result['rss_kb']}")
            if result.get("uss_kb") is not None:
                print(f"Max USS (KB): {result['uss_kb']}")
    finally:
        if wordlist_path:
            wordlist_path.unlink(missing_ok=True)
        if rules_path and rules_path != wordlist_path:
            rules_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
