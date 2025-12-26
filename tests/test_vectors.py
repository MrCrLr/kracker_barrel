import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.hash_handler import crack_chunk, init_worker
from utils.detector import Detector

PASSWORD = "vectorpass"

VECTORS = {
    "argon": "$argon2id$v=19$m=1024,t=1,p=1$EOG3ve/WbR81Gazyol08xw$XaqQWIai3rBedQjFi2PFr2DzfKVIzi1Phf7qB95ZxrM",
    "bcrypt": "$2b$05$QgKNUJxd9DLxLp73cY.qNOkPaIB/MDaXBv0jN0MNfTIMLsSteYJLq",
    "scrypt": "$scrypt$n=256,r=8,p=1$FKuHtwX1q_S0HGRc$193c8ecabf7f5977d30cceaaf4bd8a50fffdf02f9117c3411860f639e1327670",
    "pbkdf2": "$pbkdf2$a=sha256,i=1000$THYA0390NPJAdyAK$20d6334928f31decaf623f6481afb5599d6e9c9f8052ab888b7f085dfafe811d",
    "md5": "$md5$abda8d7f050c7a7219e19a17df58ad97",
    "ntlm": "$ntlm$9e36e8992ac5c262624646ce6d3c7f27",
    "sha256": "$sha256$580d6609f79a6f1ab5a95591d6abe40c18d5f0aae468772114df5063b22d45c4",
    "sha512": "$sha512$8af9ba74c1dc0d00fddfaa427cdec6d17115c29cbd6e1766bbc681b26677d034abd1a21765dfd92562cadc80f992261e2efde7ab667cff1db61e4391eb2526f6",
}


def test_vectors_detect_and_verify():
    candidates = [b"wrong", PASSWORD.encode("utf-8")]
    for hash_type, hash_value in VECTORS.items():
        detected = Detector.detect([hash_value])
        assert detected == hash_type
        init_worker(hash_type, [hash_value], None)
        results, _ = crack_chunk(candidates)
        assert hash_value in results
        assert results[hash_value] == PASSWORD


if __name__ == "__main__":
    test_vectors_detect_and_verify()
    print("Vector tests passed.")
