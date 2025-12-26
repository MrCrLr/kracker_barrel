import hashlib

from core.hash_handler import HashHandler


class SHA256Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()
        self.log_parameters()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the SHA-256 hash metadata to extract the hash to crack.
        """
        parameters = []

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Check if it follows the NTLM format
            if len(parts) == 3 and len(parts[2]) == 64:
                # Proceed with the hash
                parameters.append({
                    "full_hash": hash_digest,
                    "target_hash": self.hex_to_bytes(parts[2]),
                    "encoding": "UTF-8",
                    "format_length": len(parts[2]),
                })
            else:
                raise ValueError(f"Invalid SHA-256 hash format: {self.hash_digest_with_metadata}")
        return parameters

    def log_parameters(self):
        """Return a formatted log message for parameters."""
        first_entry = self.parameters[0]
        return self.format_standard_log(first_entry["encoding"], first_entry["format_length"])

    def verify(self, chunk):
        """
        Verify the password by calculating its SHA-512 hash and comparing it.
        """
        matches = {}
        for password in chunk:
            try:
                sha256_hash = hashlib.sha256(password).digest()
                for entry in self.parameters:
                    if sha256_hash == entry["target_hash"]:
                        matches[entry["full_hash"]] = self.decode_password(password)
            except Exception as e:
                print(f"Error during SHA-256 hash verification: {e}")

        return matches
