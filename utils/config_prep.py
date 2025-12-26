from pathlib import Path

from core.rule_setup import prepare_rule_config
from utils.detector import Detector


def _resolve_target_path(target_name):
    return Path("data") / target_name


def build_config(args):
    cfg = {
        "operation": args.operation,
        "target_file": _resolve_target_path(args.target_file),
        "password_list_path": Path("refs") / args.password_list if args.password_list else None,
        "rules_file": args.rules_file or args.rules,
        "rule_wordlist": args.password_list or args.wordlist1,
        "mask_pattern": args.pattern,
        "custom_strings": args.custom if args.custom else None,
        "brute_settings": {
            "charset": args.charset if args.charset else None,
            "min": args.min,
            "max": args.max,
        },
        "max_expansions_per_word": args.max_expansions_per_word,
        "max_candidates": args.max_candidates,
        "workers": args.workers,
        "batch_size": args.batch_size,
    }

    return prepare_rule_config(cfg)


def apply_defaults(cfg, hash_type):
    cpu_count = Detector.get_cpu_count()
    expensive_hashes = {"bcrypt", "argon", "scrypt", "pbkdf2"}

    workers = cfg.get("workers")
    batch_size = cfg.get("batch_size")
    workers_defaulted = False
    batch_size_defaulted = False

    if workers is not None and workers <= 0:
        raise ValueError("--workers must be a positive integer.")
    if batch_size is not None and batch_size <= 0:
        raise ValueError("--batch-size must be a positive integer.")

    if workers is None:
        cap = 4 if hash_type in expensive_hashes else 6
        workers = min(cpu_count, cap)
        workers_defaulted = True
    if batch_size is None:
        if hash_type in expensive_hashes:
            batch_size = 1000
        else:
            batch_size = 20000
        batch_size_defaulted = True

    cfg["workers"] = workers
    cfg["batch_size"] = batch_size
    cfg["workers_defaulted"] = workers_defaulted
    cfg["batch_size_defaulted"] = batch_size_defaulted
