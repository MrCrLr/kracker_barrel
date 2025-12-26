import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.rules_gen import Rule, apply_rule, apply_rules


def test_apply_rule_single():
    assert list(apply_rule("pass", Rule("APPEND", "123"))) == ["pass123"]
    assert list(apply_rule("pass", Rule("PREPEND", "pre"))) == ["prepass"]
    assert list(apply_rule("pass", Rule("CAPITALIZE"))) == ["Pass"]
    assert list(apply_rule("pass", Rule("REVERSE"))) == ["ssap"]
    assert list(apply_rule("password", Rule("LEETSPEAK"))) == ["p@$$w0rd"]


def test_apply_rules_ordered_deduped():
    rules = [
        Rule("APPEND", "1"),
        Rule("APPEND", "1"),
        Rule("REVERSE"),
    ]
    results = list(apply_rules("ab", rules))
    assert results == ["ab1", "ba"]


if __name__ == "__main__":
    test_apply_rule_single()
    test_apply_rules_ordered_deduped()
    print("Rule tests passed.")
