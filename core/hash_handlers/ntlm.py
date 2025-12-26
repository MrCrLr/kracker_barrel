from Crypto.Hash import MD4

from core.hash_handler import HashHandler


class NTLMHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()
        self.log_parameters()

    def parse_hash_digest_with_metadata(self):
        """
        Parse the NTLM hash metadata and extract relevant parameters.
        """
        parameters = []  # Store parsed parameters for each hash

        # Example NTLM format: $NTLM$<32-character hash>
        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            if len(parts) == 3 and len(parts[2]) == 32:
                target_hash = self.hex_to_bytes(parts[2])  # Convert hex to bytes
                parameters.append({
                    "full_hash": hash_digest,
                    "target_hash": target_hash,
                    "hash_func": "MD4",
                    "encoding": "UTF-16LE",
                    "length": len(parts[2]),
                })
            else:
                raise ValueError(f"Invalid NTLM hash format: {hash_digest}")

        return parameters

    def log_parameters(self):
        first_entry = self.parameters[0]  # Use the first hash for metadata
        log_message = (
            f"underlying algorithm={first_entry['hash_func']}, "
            f"encoding={first_entry['encoding']}, "
            f"hash length={first_entry['length']}"
        )
        return log_message

    def verify(self, chunk):
        """
        Verify the password by calculating its NTLM hash and comparing it with the target hashes.
        """
        matches = {}
        for password in chunk:
            try:
                password_text = self.decode_password(password)
                ntlm_hash = MD4.new()
                ntlm_hash.update(password_text.encode("utf-16le"))
                computed_hash = ntlm_hash.digest()

                # Check if the computed hash matches any target hash
                for entry in self.parameters:
                    if computed_hash == entry["target_hash"]:
                        matches[entry["full_hash"]] = password_text
            except Exception as e:
                print(f"Error during NTLM hash verification: {e}")

        return matches

    @staticmethod
    def hex_to_bytes(hex_string):
        """
        Convert a hex string to bytes.
        """
        return bytes.fromhex(hex_string)
