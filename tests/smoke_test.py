import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.hashmaker import HashMaker
from core.hash_handler import crack_chunk, init_worker


def run_smoke_tests():
    password = "smoke123"
    candidates = [b"wrong", password.encode("utf-8")]

    hash_maker = HashMaker(
        operation="argon",
        passwords=[password],
        output_file="smoke_test.txt",
        test_mode=True,
        secure_mode=False,
    )

    hash_sets = {
        "argon": hash_maker.compute_argon(**hash_maker.parameters["argon"]),
        "bcrypt": hash_maker.compute_bcrypt(**hash_maker.parameters["bcrypt"]),
        "scrypt": hash_maker.compute_scrypt(**hash_maker.parameters["scrypt"]),
        "pbkdf2": hash_maker.compute_pbkdf2(**hash_maker.parameters["pbkdf2"]),
        "md5": hash_maker.compute_md5(),
        "ntlm": hash_maker.compute_ntlm(),
        "sha256": hash_maker.compute_sha256(),
        "sha512": hash_maker.compute_sha512(),
    }

    failures = []
    for hash_type, hashes in hash_sets.items():
        init_worker(hash_type, hashes, None)
        results, _ = crack_chunk(candidates)
        if not results:
            failures.append(hash_type)

    if failures:
        raise AssertionError(f"Smoke tests failed for: {', '.join(failures)}")


if __name__ == "__main__":
    try:
        run_smoke_tests()
    except Exception as exc:
        print(f"Smoke tests failed: {exc}")
        sys.exit(1)
    print("Smoke tests passed.")
