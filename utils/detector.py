import os
from core.hash_handler import HashHandler


class Detector:
    HASH_MAP = {
        "argon2id": "argon",
        "2b": "bcrypt",
        "pbkdf2": "pbkdf2",
        "scrypt": "scrypt",
        "ntlm": "ntlm",
        "md5": "md5",
        "sha256": "sha256",
        "sha512": "sha512",
    }


    @staticmethod
    def detect(hash_metadata: list) -> str:
        """
        Detects the hash type from the provided hash metadata.
        Args:
            hash_metadata: List of hash strings to crack.

        Returns:
            str: The detected hash type.
        """
        if not hash_metadata:
            raise ValueError("No hashes provided for detection.")

        sample = hash_metadata[0].strip()
        if "$" in sample:
            try:
                type_check = sample.split("$", 2)[1]
                return Detector.HASH_MAP[type_check]
            except (KeyError, IndexError):
                raise ValueError(
                    f"Unknown or malformed hash format. Available types: {', '.join(Detector.HASH_MAP.keys())}"
                )

        raise ValueError(
            "Raw hex digests are not supported. Expected formats like $argon2id$, $pbkdf2$, "
            "$scrypt$, $2b$, $ntlm$, $md5$, $sha256$, or $sha512$."
        )


    @staticmethod
    def initialize(hash_metadata: list, hash_type: str):
        """
        Initializes the appropriate hash handler for the detected hash type.
        Args:
            hash_metadata: List of hash strings to crack.
            hash_type: The detected hash type.

        Returns:
            A hash handler instance appropriate for the hash type.
        """
        handlers = {
            "argon": HashHandler.Argon2Handler,
            "scrypt": HashHandler.ScryptHandler,
            "pbkdf2": HashHandler.PBKDF2Handler,
            "bcrypt": HashHandler.BcryptHandler,
            "ntlm": HashHandler.NTLMHandler,
            "md5": HashHandler.MD5Handler,
            "sha256": HashHandler.SHA256Handler,
            "sha512": HashHandler.SHA512Handler,
        }
        try:
            return handlers[hash_type](hash_metadata)
        except KeyError:
            raise ValueError(
                f"No handler available for hash type: {hash_type}. Supported types: {', '.join(handlers.keys())}"
            )


    @staticmethod
    def get_cpu_count():
        try:
            # Use process-specific CPU count if available
            return len(os.sched_getaffinity(0))
        except AttributeError:
            # Fallback for Python <3.4 (no sched_getaffinity) or systems without affinity
            try:
                return os.cpu_count()
            except NotImplementedError:
                # Fallback if CPU count cannot be determined
                return 1
