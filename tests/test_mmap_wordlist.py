import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.file_io import mmap_wordlist


def test_mmap_wordlist_offsets(tmp_path: Path = Path("tests/_tmp")):
    tmp_path.mkdir(parents=True, exist_ok=True)
    wordlist_path = tmp_path / "mmap_words.txt"
    wordlist_path.write_bytes(b"alpha\n\nbravo\r\ncharlie")

    mm, offsets = mmap_wordlist(wordlist_path)
    try:
        lines = [mm[start:end] for start, end in offsets]
        assert lines == [b"alpha", b"bravo", b"charlie"]
    finally:
        mm.close()


if __name__ == "__main__":
    test_mmap_wordlist_offsets()
    print("mmap wordlist tests passed.")
