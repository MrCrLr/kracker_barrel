import bcrypt

from core.hash_handler import HashHandler


class BcryptHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()
        self.log_parameters()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the bcrypt metadata from hash_digest_with_metadata and returns parameters.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            params = hash_digest.split("$")
            if len(params) != 4:
                raise ValueError(f"Invalid bcrypt hash format: {hash_digest}")

            # Extract version and rounds
            version = params[1]
            rounds = int(params[2])

            # Store all parameters for each hash
            parameters.append({
                "full_hash": hash_digest,
                "hash_bytes": hash_digest.encode("utf-8"),
                "version": version,
                "rounds": rounds,
            })

        return parameters

    def log_parameters(self):
        first_entry = self.parameters[0]
        log_message = (f"version={first_entry['version']}, rounds={first_entry['rounds']}")
        return log_message

    def verify(self, chunk):
        """
        Verifies a potential password against the stored bcrypt hashes.
        """
        matches = {}
        for password in chunk:
            try:
                for entry in self.parameters:
                    target_hash = entry["hash_bytes"]

                    if bcrypt.checkpw(password, target_hash):
                        matches[entry["full_hash"]] = self.decode_password(password)
            except bcrypt.error as e:
                print(f"Error during bcrypt verification: {e}")

        return matches
