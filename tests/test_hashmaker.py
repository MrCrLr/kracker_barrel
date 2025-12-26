import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core.hashmaker as hashmaker
from core.hashmaker import HashMaker, get_command_line_args


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def test_output_file_none_does_not_crash():
    maker = HashMaker("md5", ["alpha"], output_file=None, test_mode=False, secure_mode=False)
    hashes = maker.compute_md5()
    result = maker._save_to_file(hashes, "md5")
    assert result is None


def test_mutually_exclusive_modes():
    try:
        get_command_line_args(["-a", "md5", "-t", "-s"])
    except SystemExit:
        return
    raise AssertionError("Expected mutually exclusive mode flags to error.")


def test_deterministic_salts_are_stable():
    passwords = ["alpha", "beta"]
    maker_one = HashMaker(
        "pbkdf2",
        passwords,
        output_file=None,
        test_mode=True,
        secure_mode=False,
        deterministic=True,
        seed="unit-seed",
    )
    maker_two = HashMaker(
        "pbkdf2",
        passwords,
        output_file=None,
        test_mode=True,
        secure_mode=False,
        deterministic=True,
        seed="unit-seed",
    )
    assert maker_one.compute_pbkdf2(**maker_one.parameters["pbkdf2"]) == maker_two.compute_pbkdf2(**maker_two.parameters["pbkdf2"])

    maker_three = HashMaker(
        "scrypt",
        passwords,
        output_file=None,
        test_mode=True,
        secure_mode=False,
        deterministic=True,
        seed="unit-seed",
    )
    maker_four = HashMaker(
        "scrypt",
        passwords,
        output_file=None,
        test_mode=True,
        secure_mode=False,
        deterministic=True,
        seed="unit-seed",
    )
    assert maker_three.compute_scrypt(**maker_three.parameters["scrypt"]) == maker_four.compute_scrypt(**maker_four.parameters["scrypt"])


def test_plaintext_metadata_requires_flag():
    tmp_dir = Path("tests/_tmp/hashmaker")
    _ensure_dir(tmp_dir)
    hashmaker.DATA_DIR = tmp_dir

    maker = HashMaker(
        "md5",
        ["alpha"],
        output_file="hashes.txt",
        test_mode=False,
        secure_mode=False,
        include_plaintext_metadata=False,
    )
    hashes = maker.compute_md5()
    maker._save_to_file(hashes, "md5")
    hash_path = maker.file_path
    assert hash_path is not None and hash_path.exists()
    metadata_path = hash_path.with_name(hash_path.stem + "_metadata" + hash_path.suffix)
    assert not metadata_path.exists()

    maker_with_metadata = HashMaker(
        "md5",
        ["alpha"],
        output_file="hashes_with_meta.txt",
        test_mode=False,
        secure_mode=False,
        include_plaintext_metadata=True,
    )
    hashes_with_meta = maker_with_metadata.compute_md5()
    maker_with_metadata._save_to_file(hashes_with_meta, "md5")
    meta_path = maker_with_metadata.file_path.with_name(
        maker_with_metadata.file_path.stem + "_metadata" + maker_with_metadata.file_path.suffix
    )
    assert meta_path.exists()
    assert "Password:" in meta_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    test_output_file_none_does_not_crash()
    test_mutually_exclusive_modes()
    test_deterministic_salts_are_stable()
    test_plaintext_metadata_requires_flag()
    print("HashMaker tests passed.")
