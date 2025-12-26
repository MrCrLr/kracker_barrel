import base64

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.hash_handler import HashHandler


class PBKDF2Handler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()
        self.log_parameters()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the PBKDF2 metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            # Split the hash digest into components
            parts = hash_digest.split("$")
            if len(parts) != 5 or parts[1] != "pbkdf2":
                raise ValueError(f"Invalid PBKDF2 hash format: {hash_digest}")

            try:
                # Parse parameters into a dictionary
                param_string = parts[2]
                param_dict = dict(param.split("=") for param in param_string.split(","))

                # Decode salt and hash
                salt_b64 = parts[3]
                hash_hex = parts[4]

                salt = base64.urlsafe_b64decode(salt_b64)
                target_hash = bytes.fromhex(hash_hex)

                # Calculate lengths
                hash_length = len(target_hash)
                salt_length = len(salt)

                # Determine algorithm based on hash length if "a" is not provided
                algorithm = param_dict.get("a", None)
                if not algorithm:
                    if hash_length == 32:
                        algorithm = "sha256"
                    elif hash_length == 64:
                        algorithm = "sha512"
                    else:
                        raise ValueError(f"Unknown algorithm for hash length: {hash_length}")

                # Extract iterations
                iterations = int(param_dict.get("i", 0))  # Iterations count
                if not iterations > 0:
                    raise ValueError("PBKDF2 iterations must be a positive integer")

                # Store all parameters in the list
                parameters.append({
                    "full_hash": hash_digest,
                    "algorithm": algorithm,
                    "iterations": iterations,
                    "hash_length": hash_length,
                    "salt_length": salt_length,
                    "salt": salt,
                    "target_hash": target_hash,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing PBKDF2 parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        first_entry = self.parameters[0]
        log_message = (
            f"algorithm={first_entry['algorithm']}, iterations={first_entry['iterations']}, "
            f"hash length={first_entry['hash_length']}, salt length={first_entry['salt_length']}"
        )
        return log_message

    def verify(self, chunk):
        """
        Verifies a potential password against a list of stored PBKDF2 hashes.
        """
        matches = {}
        for password in chunk:
            for entry in self.parameters:
                algorithm_name = entry["algorithm"]
                hash_length = entry["hash_length"]
                iterations = entry["iterations"]
                salt = entry["salt"]
                target_hash = entry["target_hash"]

                algorithm = self.parse_algorithm(algorithm_name)

                # Create a new PBKDF2HMAC instance dynamically
                hash_processor = PBKDF2HMAC(
                    algorithm=algorithm,
                    length=hash_length,
                    salt=salt,
                    iterations=iterations,
                )

                try:
                    if hash_processor.derive(password) == target_hash:
                        matches[entry["full_hash"]] = self.decode_password(password)

                except InvalidKey:
                    continue  # Continue to the next entry

        return matches
