# **Kracker Barrel: Multiprocessing Password Cracker**

Kracker Barrel is a small, **educational password‑hash cracking lab tool** for **offline verification** against common hash formats.  
Use only on hashes you own or have explicit permission to test.

---

## **Table of Contents**
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Dictionary mode](#dictionary-mode)
  - [Mask mode](#mask-mode)
  - [Brute-force mode](#brute-force-mode)
  - [Rule mode](#rule-mode)
- [Supported Hash Formats](#supported-hash-formats)
- [Performance & Concurrency](#performance--concurrency)
- [Benchmarking](#benchmarking)
- [Configuration File](#configuration-file)
- [Development](#development)
- [License](#license)

---

## **Features**
- **Auto-detection** of hash type/parameters from metadata-style prefixes.
- Modes: **dictionary**, **brute-force**, **mask**, **rules**
- **Single-layer multiprocessing** with per-worker handler init (fast + predictable).
- **Low-IPC design**: workers pull **ranges/indices** (avoids pickling huge candidate lists).
- Wordlist loading options for dict/rule:
  - `mmap` path for low-copy access
  - `list` path for comparisons/edge cases
- Rule-mode guardrails:
  - `--max-expansions-per-word`
  - `--max-candidates`
- Benchmark harness with **sweep** + optional **CSV** export.

---

## **Installation**

This repo is designed to run with **uv**.

```bash
uv sync
```

---

## **Quick Start**

> Target hash files are plain text: **one hash per line**.

```bash
uv run python main.py -d data/hash_md5.txt refs/tiny_wordlist.txt
```

---

## **Usage**

## **Modes (compact reference)**

| Mode | Flag | Required inputs | Common options | Example |
|---|---|---|---|---|
| Dictionary | `-d` | `HASH_FILE` `WORDLIST` | `--workers`, `--batch-size`, `--wordlist-load {mmap,list}` | `uv run python main.py -d data/hash_md5.txt refs/tiny_wordlist.txt` |
| Brute-force | `-b` | `HASH_FILE` | `--charset`, `--min`, `--max`, `--workers`, `--batch-size` | `uv run python main.py -b data/hash_bcrypt.txt --charset ab1 --min 3 --max 3` |
| Mask | `-m` | `HASH_FILE` | `--pattern`, `--custom`, `--workers`, `--batch-size` | `uv run python main.py -m data/hash_sha256.txt --pattern "?l?l?d"` |
| Rules | `-r` | `HASH_FILE` `WORDLIST` | `--rules`, `--max-expansions-per-word`, `--max-candidates`, `--workers`, `--batch-size`, `--wordlist-load {mmap,list}` | `uv run python main.py -r data/hash_md5.txt refs/tiny_wordlist.txt --rules rules.txt --max-expansions-per-word 50 --max-candidates 200000` |

> `HASH_FILE` contains one target hash per line. CLI flags override config values if you use a YAML config.


### **Dictionary mode**

```bash
uv run python main.py -d data/hash_md5.txt refs/tiny_wordlist.txt
```

### **Mask mode**

```bash
uv run python main.py -m data/hash_sha256.txt --pattern "?l?l?d"
```

### **Brute-force mode**

```bash
uv run python main.py -b data/hash_bcrypt.txt --charset ab1 --min 3 --max 3
```

### **Rule mode**

```bash
uv run python main.py -r data/hash_md5.txt refs/tiny_wordlist.txt --rules rules.txt \
  --max-expansions-per-word 50 --max-candidates 200000
```

---

## **CLI reference (common flags)**

| Flag | Meaning |
|---|---|
| `--workers N` | Worker process count (auto defaults by hash “cost”; overrides allowed) |
| `--batch-size N` | Work size per task (auto defaults by hash “cost”; overrides allowed) |
| `--wordlist-load {mmap,list}` | Dict/rule wordlist loading strategy (bench/debug/compat) |
| `--max-expansions-per-word N` | Rule-mode per-base-word expansion cap |
| `--max-candidates N` | Rule-mode global candidate cap |

---

## **Supported Hash Formats**

> Hashes are expected in metadata-style formats (prefix-based) where applicable.

| Algorithm | Notes / parameters auto-parsed |
|---|---|
| Argon2id | time cost, memory cost, parallelism |
| bcrypt | cost factor |
| scrypt | N / r / p |
| PBKDF2 | hash alg, iterations, salt |
| NTLM | UTF-16LE handling |
| MD5 | raw digest verification |
| SHA-256 | raw digest verification |
| SHA-512 | raw digest verification |

---

## **Performance & Concurrency**

Kracker Barrel uses a single `ProcessPoolExecutor` with:
- **Per-worker initialization** (hash handler and mode config built once).
- **Range/index-based work units** (minimizes IPC/pickling overhead).
- **Stop-event fast cancellation** for responsive early exits.

Defaults are printed in the startup banner and can be overridden via `--workers` and `--batch-size`.

---

## **Benchmarking**

Single run:

```bash
uv run python bench.py --mode dict --hash-type md5 --workers 4 --batch-size 20000 --candidates 5000000
```

Sweep (find best workers/batch-size combo):

```bash
uv run python bench.py --sweep \
  --mode dict --hash-type md5 \
  --workers-list 1,2,4,6,8 \
  --batch-sizes 2000,20000,100000 \
  --candidates 5000000 --csv bench.csv
```

### Wordlist loading comparisons

| Option | When to use |
|---|---|
| `--wordlist-load mmap` | Default-ish path for low-copy access; better scalability on large wordlists |
| `--wordlist-load list` | Baseline comparisons; simplest behavior |

### RSS vs mmap note (macOS)

On macOS, `ru_maxrss` can look **higher** with `mmap` because file-backed mapped pages are counted in RSS.  
That does **not** necessarily mean higher *private* memory usage. For private-memory views, prefer tools like `vmmap`
or USS metrics when available.

---

## **Configuration File**

There is a YAML config loader for convenience. It is typically used when you run with **no CLI args**;  
CLI arguments override config.

**Example keys (high level):**

| Key | Meaning |
|---|---|
| `operation` | `dict` \| `brut` \| `mask` \| `rule` |
| `target_file` | Path to hashes file |
| `password_list` | Wordlist path (dict/rule) |
| `pattern` | Mask pattern (mask mode) |
| `charset`, `min`, `max` | Brut parameters |
| `rules` | Rules file (rule mode) |
| `workers`, `batch-size` | Concurrency overrides (optional) |

See `config.example.yaml` for a full template.

---

## **Development**

Quick check:

```bash
uv sync && uv run python tests/smoke_test.py
```

Tests:

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

### HashMaker usage

Examples:

```bash
# Kracker-compatible hashes to stdout
python core/hashmaker.py -a pbkdf2 -p "example"

# Write hashes to a file in data/
python core/hashmaker.py -a scrypt -p "example" -o test_hashes.txt

# Deterministic fixtures (reproducible salts)
python core/hashmaker.py -a pbkdf2 -p "example" -d --seed "fixture-seed"

# Passwords from a file (one per line)
python core/hashmaker.py -a bcrypt -i refs/wordlist.txt
```

### Adding hash algorithms

- Add a handler module under `core/hash_handlers/` (one file per algorithm) and expose a handler class.
- Register the handler in `core/hash_handlers/__init__.py` under `HANDLER_IMPORTS`.
- Add the hash prefix mapping in `utils/detector.py` so `Detector.detect` can route to your handler.
- Keep `core/hash_handler.py` as the shared base/shim; no changes required there for new modules.

---

## **License**

MIT. See [LICENSE](LICENSE).
