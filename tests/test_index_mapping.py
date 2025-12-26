import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.brut_gen import build_length_table, index_to_brut_candidate
from core.mask_gen import compile_mask_alphabets, index_to_mask_candidate, get_mask_space_size


def test_brut_index_mapping():
    charset = b"ab"
    table = build_length_table(1, 2, len(charset))
    expected = [b"a", b"b", b"aa", b"ab", b"ba", b"bb"]
    results = [index_to_brut_candidate(i, charset, table) for i in range(len(expected))]
    assert results == expected


def test_mask_index_mapping():
    alphabets = compile_mask_alphabets("?c?c", "ab")
    assert alphabets == [b"ab", b"ab"]
    assert get_mask_space_size(alphabets) == 4
    expected = [b"aa", b"ab", b"ba", b"bb"]
    results = [index_to_mask_candidate(i, alphabets) for i in range(4)]
    assert results == expected


if __name__ == "__main__":
    test_brut_index_mapping()
    test_mask_index_mapping()
    print("Index mapping tests passed.")
