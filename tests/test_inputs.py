import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.kracker import Kracker
from utils.config_prep import build_config
from utils.detector import Detector
from utils.file_io import load_target_hash
from core.rules_gen import load_rules

MD5_HASH = "$md5$abda8d7f050c7a7219e19a17df58ad97"


def _write_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _make_args(**overrides):
    base = dict(
        operation="rule",
        target_file="tmp_hashes.txt",
        password_list="tmp_words.txt",
        rules_file="tmp_rules.txt",
        rules=None,
        wordlist1=None,
        wordlist2=None,
        pattern=None,
        custom=None,
        charset="abc",
        min=1,
        max=1,
        workers=None,
        batch_size=None,
        max_expansions_per_word=None,
        max_candidates=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_detector_unknown_format():
    try:
        Detector.detect(["$unknown$abc"])
    except ValueError as exc:
        assert "Unknown or malformed" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unknown format")


def test_load_target_hash_empty(tmp_path: Path = Path("tests/_tmp")):
    tmp_path.mkdir(parents=True, exist_ok=True)
    empty_file = tmp_path / "empty_hashes.txt"
    _write_file(empty_file, "")
    assert load_target_hash(empty_file) == []


def test_empty_rules_or_wordlist_fail_fast(tmp_path: Path = Path("tests/_tmp")):
    tmp_path.mkdir(parents=True, exist_ok=True)
    data_dir = ROOT / "data"
    refs_dir = ROOT / "refs"
    data_dir.mkdir(exist_ok=True)
    refs_dir.mkdir(exist_ok=True)

    hashes_file = data_dir / "tmp_hashes.txt"
    _write_file(hashes_file, f"{MD5_HASH}\n")

    empty_rules = refs_dir / "tmp_rules.txt"
    empty_wordlist = refs_dir / "tmp_words.txt"
    _write_file(empty_rules, "")
    _write_file(empty_wordlist, "")

    args = _make_args(password_list=empty_wordlist.name, rules_file=empty_rules.name)

    try:
        cfg = build_config(args)
        Kracker(cfg)
    except ValueError as exc:
        assert "Rule wordlist is empty" in str(exc) or "at least one rule" in str(exc)
    else:
        raise AssertionError("Expected ValueError for empty rules or wordlist")


if __name__ == "__main__":
    test_detector_unknown_format()
    test_load_target_hash_empty()
    test_empty_rules_or_wordlist_fail_fast()
    print("Input tests passed.")
