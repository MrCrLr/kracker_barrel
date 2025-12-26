from importlib import import_module
from cryptography.hazmat.primitives import hashes
from core.hash_handlers.base import BaseHashHandler


_HANDLER_EXPORTS = {
    "Argon2Handler": "core.hash_handlers.argon2",
    "ScryptHandler": "core.hash_handlers.scrypt",
    "PBKDF2Handler": "core.hash_handlers.pbkdf2",
    "BcryptHandler": "core.hash_handlers.bcrypt",
    "NTLMHandler": "core.hash_handlers.ntlm",
    "MD5Handler": "core.hash_handlers.md5",
    "SHA256Handler": "core.hash_handlers.sha256",
    "SHA512Handler": "core.hash_handlers.sha512",
}


class HashHandler(BaseHashHandler):
    # Define a mapping of algorithm names to their respective hash objects
    ALGORITHM_MAP = {
        "sha512": hashes.SHA512,
        "sha256": hashes.SHA256,
        "sha1": hashes.SHA1,
        # Add more algorithms as needed
    }


    def __init__(self, hash_digest_with_metadata):
        self.hash_digest_with_metadata = hash_digest_with_metadata  # Input-specific data
        self.parameters = []  # To be derived in subclasses


    @staticmethod
    def hex_to_bytes(hash_string):
        """Convert a hexadecimal hash string to bytes."""
        try:
            return bytes.fromhex(hash_string)
        except ValueError:
            raise ValueError("Invalid hash format (not hexadecimal)")


    @staticmethod
    def format_standard_log(encoding, format_length):
        bits = format_length * 4
        byte_length = format_length // 2
        log_message = (
            f"encoding={encoding}, hash format={bits} bits "
            f"({byte_length} bytes), {format_length}-character hexadecimal string"
        )
        return log_message


    @staticmethod
    def decode_password(password):
        if isinstance(password, (bytes, bytearray)):
            return password.decode("utf-8", errors="replace")
        return str(password)


    def parse_algorithm(self, algorithm_name):
        """
        Dynamically parse and return the hash algorithm object based on its name.
        """
        algorithm_name = algorithm_name.lower()  # Ensure case-insensitivity
        algorithm_class = self.ALGORITHM_MAP.get(algorithm_name)
        if not algorithm_class:
            raise ValueError(f"Unsupported algorithm: {algorithm_name}")
        return algorithm_class()


    def parse_hash_digest_with_metadata(self):
        """Abstract method to parse metadata."""
        raise NotImplementedError("Subclasses must implement this method.")


    def verify(self, potential_password_match):
        """Abstract method to verify passwords."""
        raise NotImplementedError("Subclasses must implement this method.")
        

    def log_parameters(self):
        """Abstract method for logging parameters."""
        raise NotImplementedError("Subclasses must implement this method.")


def __getattr__(name):
    module_name = _HANDLER_EXPORTS.get(name)
    if not module_name:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
    module = import_module(module_name)
    return getattr(module, name)


__all__ = ["HashHandler", *sorted(_HANDLER_EXPORTS.keys())]


_HANDLER = None
_STOP = None
_MMAP = None
_OFFSETS = None
_WORDLIST_BYTES = None
_RULES = None
_MODE = None
_MAX_EXPANSIONS_PER_WORD = None
_MAX_CANDIDATES = None
_CHARSET_BYTES = None
_LENGTH_TABLE = None
_MASK_ALPHABETS = None
_MICRO_BATCH = 1024
_REPORT_RSS = False
_WORDLIST_LOAD_MODE = "mmap"


def get_hash_handler(hash_type, hash_digest_with_metadata):
    from core.hash_handlers import get_handler

    try:
        return get_handler(hash_type, hash_digest_with_metadata)
    except ValueError as e:
        raise ValueError(f"Error determining hash type or handler: {e}")


def init_worker(hash_type, hash_digest_with_metadata, stop_event):
    global _HANDLER, _STOP
    _HANDLER = get_hash_handler(hash_type, hash_digest_with_metadata)
    _STOP = stop_event


def init_worker_range(
    hash_type,
    hash_digest_with_metadata,
    stop_event,
    mode,
    wordlist_path=None,
    rules_file=None,
    max_expansions_per_word=None,
    max_candidates=None,
    brut_settings=None,
    mask_pattern=None,
    custom_strings=None,
    micro_batch=1024,
    report_rss=False,
    wordlist_load_mode="mmap",
):
    global _HANDLER, _STOP, _WORDLIST_BYTES, _RULES, _MODE, _MAX_EXPANSIONS_PER_WORD, _MAX_CANDIDATES
    global _CHARSET_BYTES, _LENGTH_TABLE, _MASK_ALPHABETS, _MICRO_BATCH, _REPORT_RSS, _WORDLIST_LOAD_MODE
    global _MMAP, _OFFSETS
    _HANDLER = get_hash_handler(hash_type, hash_digest_with_metadata)
    _STOP = stop_event
    _MODE = mode
    _MAX_EXPANSIONS_PER_WORD = max_expansions_per_word
    _MAX_CANDIDATES = max_candidates
    _MICRO_BATCH = micro_batch
    _REPORT_RSS = report_rss
    _WORDLIST_LOAD_MODE = wordlist_load_mode

    _MMAP = None
    _OFFSETS = None
    _WORDLIST_BYTES = None
    if wordlist_path:
        if wordlist_load_mode == "list":
            with open(wordlist_path, "r", encoding="latin-1", errors="replace") as file:
                wordlist = []
                for line in file:
                    cleaned = line.strip()
                    if not cleaned:
                        continue
                    if "�" in cleaned:
                        continue
                    wordlist.append(cleaned.encode("utf-8"))
                _WORDLIST_BYTES = wordlist
        else:
            from utils.file_io import mmap_wordlist

            _MMAP, _OFFSETS = mmap_wordlist(wordlist_path)

    _RULES = None
    if mode == "rule":
        from core.rules_gen import load_rules

        _RULES = load_rules(rules_file)

    if mode == "brut":
        from core.brut_gen import build_length_table

        charset = brut_settings["charset"].encode("utf-8")
        _CHARSET_BYTES = charset
        _LENGTH_TABLE = build_length_table(brut_settings["min"], brut_settings["max"], len(charset))

    if mode == "mask":
        from core.mask_gen import compile_mask_alphabets

        _MASK_ALPHABETS = compile_mask_alphabets(mask_pattern, custom_strings)


# Sends a chunk of passwords to be verified instead of one at a time
def crack_chunk(chunk):
    if _STOP is not None and _STOP.is_set():
        return {}, 0

    matched_passwords = _HANDLER.verify(chunk)
    return matched_passwords, len(chunk)


def crack_range(range_tuple):
    if _STOP is not None and _STOP.is_set():
        return {}, {"base_words_processed": 0, "expanded_generated": 0, "verified_count": 0}

    start_idx, end_idx = range_tuple
    def _get_word_bytes(idx):
        if _WORDLIST_BYTES is not None:
            return _WORDLIST_BYTES[idx]
        start, end = _OFFSETS[idx]
        return _MMAP[start:end]

    def _maybe_rss(meta):
        if not _REPORT_RSS:
            return meta
        try:
            import resource
            import sys

            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # Linux reports KB, macOS reports bytes.
            if sys.platform == "darwin":
                rss = rss // 1024
            meta["rss_kb"] = rss
        except Exception:
            meta["rss_kb"] = None
        try:
            import psutil

            proc = psutil.Process()
            full_info = proc.memory_full_info()
            uss = getattr(full_info, "uss", None)
            if uss is not None:
                meta["uss_kb"] = uss // 1024
            else:
                meta["uss_kb"] = None
        except Exception:
            meta["uss_kb"] = None
        return meta

    if _MODE == "dict":
        matches = {}
        verified_count = 0
        candidates = []
        for idx in range(start_idx, end_idx):
            if _STOP is not None and _STOP.is_set():
                break
            candidates.append(_get_word_bytes(idx))
            if len(candidates) >= _MICRO_BATCH:
                batch_matches = _HANDLER.verify(candidates)
                if batch_matches:
                    matches.update(batch_matches)
                verified_count += len(candidates)
                candidates = []
        if candidates:
            batch_matches = _HANDLER.verify(candidates)
            if batch_matches:
                matches.update(batch_matches)
            verified_count += len(candidates)
        return matches, _maybe_rss({
            "base_words_processed": verified_count,
            "expanded_generated": verified_count,
            "verified_count": verified_count,
        })

    if _MODE == "rule":
        if not _RULES:
            return {}, {"base_words_processed": 0, "expanded_generated": 0, "verified_count": 0}
        expansions_per_word = len(_RULES)
        if _MAX_EXPANSIONS_PER_WORD is not None:
            expansions_per_word = min(expansions_per_word, _MAX_EXPANSIONS_PER_WORD)
        if expansions_per_word <= 0:
            return {}, {"base_words_processed": 0, "expanded_generated": 0, "verified_count": 0}

        range_cap = None
        if _MAX_CANDIDATES is not None:
            offset = start_idx * expansions_per_word
            if offset >= _MAX_CANDIDATES:
                return {}, {"base_words_processed": 0, "expanded_generated": 0, "verified_count": 0}
            remaining = _MAX_CANDIDATES - offset
            range_cap = min(remaining, (end_idx - start_idx) * expansions_per_word)

        from core.rules_gen import apply_rules

        base_words_processed = 0
        expanded_generated = 0
        candidates = []

        for idx in range(start_idx, end_idx):
            if _STOP is not None and _STOP.is_set():
                break
            word_bytes = _get_word_bytes(idx)
            word = word_bytes.decode("utf-8", errors="replace")
            base_words_processed += 1
            per_word_count = 0
            for transformed in apply_rules(word, _RULES):
                if _MAX_EXPANSIONS_PER_WORD is not None and per_word_count >= _MAX_EXPANSIONS_PER_WORD:
                    break
                if range_cap is not None and expanded_generated >= range_cap:
                    break
                candidates.append(transformed.encode("utf-8"))
                per_word_count += 1
                expanded_generated += 1
            if range_cap is not None and expanded_generated >= range_cap:
                break

        matches = _HANDLER.verify(candidates) if candidates else {}
        return matches, _maybe_rss({
            "base_words_processed": base_words_processed,
            "expanded_generated": expanded_generated,
            "verified_count": len(candidates),
        })

    if _MODE == "brut":
        from core.brut_gen import index_to_brut_candidate

        matches = {}
        verified_count = 0
        candidates = []
        for i in range(start_idx, end_idx):
            if _STOP is not None and _STOP.is_set():
                break
            candidates.append(index_to_brut_candidate(i, _CHARSET_BYTES, _LENGTH_TABLE))
            if len(candidates) >= _MICRO_BATCH:
                batch_matches = _HANDLER.verify(candidates)
                if batch_matches:
                    matches.update(batch_matches)
                verified_count += len(candidates)
                candidates = []
        if candidates:
            batch_matches = _HANDLER.verify(candidates)
            if batch_matches:
                matches.update(batch_matches)
            verified_count += len(candidates)
        return matches, _maybe_rss({
            "base_words_processed": 0,
            "expanded_generated": 0,
            "verified_count": verified_count,
        })

    if _MODE == "mask":
        from core.mask_gen import index_to_mask_candidate

        matches = {}
        verified_count = 0
        candidates = []
        for i in range(start_idx, end_idx):
            if _STOP is not None and _STOP.is_set():
                break
            candidates.append(index_to_mask_candidate(i, _MASK_ALPHABETS))
            if len(candidates) >= _MICRO_BATCH:
                batch_matches = _HANDLER.verify(candidates)
                if batch_matches:
                    matches.update(batch_matches)
                verified_count += len(candidates)
                candidates = []
        if candidates:
            batch_matches = _HANDLER.verify(candidates)
            if batch_matches:
                matches.update(batch_matches)
            verified_count += len(candidates)
        return matches, _maybe_rss({
            "base_words_processed": 0,
            "expanded_generated": 0,
            "verified_count": verified_count,
        })

    return {}, _maybe_rss({"base_words_processed": 0, "expanded_generated": 0, "verified_count": 0})
