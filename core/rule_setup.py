from pathlib import Path

from core.rules_gen import load_rules


def resolve_wordlist_path(wordlist_name):
    if not wordlist_name:
        return None
    candidate = Path(wordlist_name)
    if candidate.exists():
        return candidate
    candidate = Path("refs") / wordlist_name
    if candidate.exists():
        return candidate
    return None


def resolve_rules_path(rules_name):
    if not rules_name:
        return None
    candidate = Path(rules_name)
    if candidate.exists():
        return candidate
    candidate = Path("refs") / rules_name
    if candidate.exists():
        return candidate
    candidate = Path("core") / rules_name
    if candidate.exists():
        return candidate
    return None


def wordlist_has_entries(wordlist_path):
    with Path(wordlist_path).open("r", encoding="latin-1", errors="replace") as file:
        return any(line.strip() for line in file)


def prepare_rule_config(cfg):
    if cfg.get("operation") != "rule":
        return cfg

    rules_path = resolve_rules_path(cfg.get("rules_file"))
    rule_wordlist = cfg.get("rule_wordlist")

    if not rule_wordlist:
        raise ValueError("Rule mode requires a wordlist (password_list or --wordlist1).")
    if not rules_path:
        raise ValueError("Rule mode requires a rules file (rules_file or --rules).")

    wordlist_path = resolve_wordlist_path(rule_wordlist)
    if not wordlist_path:
        raise ValueError(f"Rule wordlist not found: {rule_wordlist}")

    max_expansions_per_word = cfg.get("max_expansions_per_word")
    if max_expansions_per_word is not None and max_expansions_per_word <= 0:
        raise ValueError("--max-expansions-per-word must be a positive integer.")

    max_candidates = cfg.get("max_candidates")
    if max_candidates is not None and max_candidates <= 0:
        raise ValueError("--max-candidates must be a positive integer.")

    if not wordlist_has_entries(wordlist_path):
        raise ValueError("Rule wordlist is empty.")

    rules = load_rules(rules_path)
    if not rules:
        raise ValueError("Rule mode requires at least one rule.")

    cfg["rules_file"] = rules_path
    cfg["password_list_path"] = wordlist_path
    cfg["rules"] = rules
    return cfg
