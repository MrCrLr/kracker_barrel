from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional


@dataclass(frozen=True)
class Rule:
    name: str
    value: Optional[str] = None


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].strip()


def load_rules(rules_file: Path) -> list[Rule]:
    """
    Load transformation rules from a file.
    Returns a list of Rule objects in file order.
    """
    rules: list[Rule] = []
    with Path(rules_file).open("r", encoding="utf-8") as file:
        for raw_line in file:
            line = _strip_comment(raw_line)
            if not line:
                continue
            parts = line.split(maxsplit=1)
            name = parts[0].upper()
            value = parts[1] if len(parts) > 1 else None
            rules.append(Rule(name=name, value=value))
    return rules


def apply_rule(word: str, rule: Rule) -> Iterable[str]:
    if rule.name == "APPEND":
        if rule.value is None:
            raise ValueError("APPEND rule requires a value.")
        return [word + rule.value]
    if rule.name == "PREPEND":
        if rule.value is None:
            raise ValueError("PREPEND rule requires a value.")
        return [rule.value + word]
    if rule.name == "CAPITALIZE":
        return [word.capitalize()]
    if rule.name == "REVERSE":
        return [word[::-1]]
    if rule.name == "LEETSPEAK":
        leetspeak = (
            word.replace("a", "@")
            .replace("o", "0")
            .replace("e", "3")
            .replace("i", "1")
            .replace("s", "$")
        )
        return [leetspeak]
    raise ValueError(f"Unknown rule: {rule.name}")


def apply_rules(word: str, rules: list[Rule]) -> Iterable[str]:
    """
    Apply transformation rules to a word in rule order.
    Returns a de-duplicated iterable while preserving order.
    """
    seen: dict[str, None] = {}
    for rule in rules:
        for transformed in apply_rule(word, rule):
            if transformed not in seen:
                seen[transformed] = None
    return seen.keys()


def generate_rule_candidates(wordlist_path: Path, rules: list[Rule]) -> Iterator[bytes]:
    with Path(wordlist_path).open("r", encoding="latin-1", errors="replace") as file:
        for line in file:
            word = line.strip()
            if not word:
                continue
            for transformed in apply_rules(word, rules):
                yield transformed.encode("utf-8")


def yield_rule_batches(generator: Iterable[bytes], batch_size: int) -> Iterator[list[bytes]]:
    batch: list[bytes] = []
    for candidate in generator:
        batch.append(candidate)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def get_rule_count(
    wordlist_path: Path,
    rules: list[Rule],
    max_expansions_per_word: Optional[int] = None,
    max_candidates: Optional[int] = None,
) -> int:
    if not rules:
        return 0
    with Path(wordlist_path).open("r", encoding="latin-1", errors="replace") as file:
        word_count = sum(1 for _ in file)
    expansions_per_word = len(rules)
    if max_expansions_per_word is not None:
        expansions_per_word = min(expansions_per_word, max_expansions_per_word)
    total = word_count * expansions_per_word
    if max_candidates is not None:
        total = min(total, max_candidates)
    return total
