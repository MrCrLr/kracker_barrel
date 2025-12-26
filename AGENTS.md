# Repository Guidelines

## Project Structure & Module Organization
- `main.py` is the entry point; it wires config, batch management, and workers.
- `core/` holds cracking logic (`kracker.py`, `hash_handler.py` shim, `hash_handlers/` per-algorithm modules) and generators (`brut_gen.py`, `mask_gen.py`, `rules_gen.py`).
- `utils/` contains CLI/config parsing, logging, reporting, and file helpers.
- `config.yaml` stores default run configuration (operation, hash type, file paths).
- `data/` is for target hash files; `refs/` is for wordlists and rules.
- `tests/` includes small validation scripts (not a formal test suite).
- `profiling/` and `logs/` capture runtime artifacts.

## Build, Test, and Development Commands
- `python3 -m venv venv` and `source venv/bin/activate` to isolate dependencies.
- `pip install -r requirements.txt` to install runtime packages.
- `python main.py -d <hash_type> data/targets.txt refs/wordlist.txt` to run a dictionary attack.
- `python main.py -m <hash_type> data/targets.txt --pattern "?l?l?d?d"` for mask-based attacks.
- `python main.py -b <hash_type> data/targets.txt --charset "abc123" --min 1 --max 4` for brute-force.
- `python core/hashmaker.py -o pbkdf2 -t output.txt` to generate test hashes.

## Coding Style & Naming Conventions
- Python: 4-space indentation, no tabs.
- Modules and functions: `snake_case`; classes: `CamelCase`; constants: `UPPER_SNAKE_CASE`.
- Keep functions focused; prefer small helpers in `utils/`.
- No enforced formatter/linter—keep diffs clean and consistent with existing style.

## Testing Guidelines
- No automated test runner is configured.
- Use the scripts in `tests/` as manual checks (e.g., `python tests/shared_mem_validation.py`).
- When adding logic in `core/`, include a quick validation path or sample hash in PR notes.

## Commit & Pull Request Guidelines
- Commit history uses descriptive sentence-case messages without prefixes; follow that pattern.
- PRs should include: purpose, key files touched, how to run (or why not), and any performance/throughput impact.
- Include sample commands or minimal reproduction steps for cracking changes.

## Security & Configuration Tips
- Only use on hashes you are authorized to test.
- Keep large wordlists in `refs/` and avoid committing them.
- Prefer `config.yaml` for repeatable runs; document new fields in the README when added.
