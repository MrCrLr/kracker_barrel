# Kracker Barrel

A small, **educational password-hash cracking lab tool** for offline verification against common hash formats.  
Use only on hashes you own or have explicit permission to test.

## Features

- Modes: **dictionary**, **brute-force**, **mask**, **rules**
- Multiple hash formats (auto-detected from metadata-style prefixes)
- Single-layer **multiprocessing** with per-worker handler init (fast + predictable)
- Range-based work units for dict/rule/brut/mask to reduce IPC overhead
- Rule-mode guardrails:
  - `--max-expansions-per-word`
  - `--max-candidates`
- Benchmark harness with sweep + CSV export
- Wordlist mmap path for dict/rule to reduce per-worker duplication

## Setup

This repo is designed to run with **uv**.

```bash
uv sync
```

## Quick start

> Target hash files are plain text: **one hash per line**.

### Dictionary mode

```bash
uv run python main.py -d data/hash_md5.txt refs/tiny_wordlist.txt
```

### Mask mode

```bash
uv run python main.py -m data/hash_sha256.txt --pattern "?l?l?d"
```

### Brute-force mode

```bash
uv run python main.py -b data/hash_bcrypt.txt --charset ab1 --min 3 --max 3
```

### Rule mode

```bash
uv run python main.py -r data/hash_md5.txt refs/tiny_wordlist.txt --rules rules.txt \
  --max-expansions-per-word 50 --max-candidates 200000
```

## Concurrency tuning

These flags are available across modes:

- `--workers N` — number of worker processes
- `--batch-size N` — work size per task

Defaults are chosen automatically based on hash "cost" (cheap vs expensive) and printed in the startup banner.  
For your machine's best values, use the benchmark sweep.

## Benchmarking

Single run:

```bash
uv run python bench.py --mode dict --hash-type md5 --workers 4 --batch-size 20000 --candidates 5000000
```

Sweep (find best config):

```bash
uv run python bench.py --sweep \
  --mode dict --hash-type md5 \
  --workers-list 1,2,4,6,8 \
  --batch-sizes 2000,20000,100000 \
  --candidates 5000000 --csv bench.csv
```

Dictionary/rule wordlist loading:
- `--wordlist-load mmap` (default) uses memory-mapped wordlists for lower duplication.
- `--wordlist-load list` loads full lists into each worker for comparison.

### RSS vs mmap note (macOS)

On macOS, `ru_maxrss` can look **higher** with `mmap` because file-backed mapped pages are counted in RSS.  
That does **not** necessarily mean higher private memory usage. For a true private-memory view, prefer USS (bench reports it
via `psutil`) or tools like `vmmap`.

## Config file

There is a YAML config loader for convenience. It is typically used when you run with **no CLI args**;  
CLI arguments override config.

See: `config.yaml` for examples.

## Development

Run tests:

```bash
uv run python tests/smoke_test.py
uv run python tests/test_vectors.py
uv run python tests/test_inputs.py
uv run python tests/test_rules.py
uv run python tests/test_index_mapping.py
uv run python tests/test_mmap_wordlist.py
```

Compile check:

```bash
uv run python -m compileall -q core utils main.py tests bench.py
```
