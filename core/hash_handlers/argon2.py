from argon2 import PasswordHasher

from core.hash_handler import HashHandler


class Argon2Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)  # Initialize parent attributes
        self.parameters = self.parse_hash_digest_with_metadata()  # Argon2-specific parameters
        self.precomputed_processors = self.precompute_processors()  # Argon2-specific processors
        self.log_parameters()  # Log initialization parameters

    def parse_hash_digest_with_metadata(self):
        """
        Parses the Argon2 metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        Format: $argon2id$v=19$m=47104,t=1,p=1$<base64-encoded-salt>$<base64-encoded-hash>
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            parts = hash_digest.split("$")

            # Validate basic structure of the hash
            if len(parts) != 6:
                raise ValueError(f"Invalid Argon2id hash format: {hash_digest}")

            try:
                algorithm = parts[1]
                version = int(parts[2].split("=")[1])

                # Parse parameters into a dictionary
                param_string = parts[3]
                param_dict = dict(param.split("=") for param in param_string.split(","))

                # Extract memory cost, time cost, and parallelism
                memory_cost = int(param_dict.get("m", 0))
                time_cost = int(param_dict.get("t", 0))
                parallelism = int(param_dict.get("p", 0))

                parameters.append({
                    "full_hash": hash_digest,
                    "algorithm": algorithm,
                    "version": version,
                    "memory_cost": memory_cost,
                    "time_cost": time_cost,
                    "parallelism": parallelism,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing Argon2 parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        first_entry = self.parameters[0]
        log_message = (
            f"version={first_entry['version']}, memory_cost={first_entry['memory_cost']},"
            f" time_cost={first_entry['time_cost']}, parallelism={first_entry['parallelism']}"
        )
        return log_message

    def precompute_processors(self):
        """
        Precomputes reusable PasswordHasher instances for each target hash.
        Returns a list of precomputed processors.
        """
        precomputed_processors = []

        for entry in self.parameters:
            precomputed_processors.append(
                PasswordHasher(
                    time_cost=entry["time_cost"],
                    memory_cost=entry["memory_cost"],
                    parallelism=entry["parallelism"],
                )
            )

        return precomputed_processors

    def verify(self, chunk):
        """
        Verifies a potential password against the precomputed processors.
        """
        matches = {}
        for password in chunk:
            password_text = self.decode_password(password)
            for entry, processor in zip(self.parameters, self.precomputed_processors):
                try:
                    if processor.verify(entry["full_hash"], password_text):
                        matches[entry["full_hash"]] = password_text
                except Exception:
                    continue
        return matches
