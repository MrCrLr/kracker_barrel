import base64

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from core.hash_handler import HashHandler


class ScryptHandler(HashHandler):
    def __init__(self, hash_digest_with_metadata):
        super().__init__(hash_digest_with_metadata)
        self.hash_digest_with_metadata = hash_digest_with_metadata
        self.parameters = self.parse_hash_digest_with_metadata()
        self.log_parameters()

    def parse_hash_digest_with_metadata(self):
        """
        Parses the scrypt metadata from hash_digest_with_metadata and decodes
        salt and target hashes for each item in the list.
        """
        parameters = []  # Store parsed parameters for each hash

        for hash_digest in self.hash_digest_with_metadata:
            # Split the hash digest into components
            parts = hash_digest.split("$")
            if len(parts) != 5 or not parts[1] == "scrypt":
                raise ValueError(f"Invalid scrypt hash format: {hash_digest}")

            try:
                # Parse parameters into a dictionary
                algorithm = parts[1]
                param_string = parts[2]
                param_dict = dict(param.split("=") for param in param_string.split(","))

                # Extract memory cost, block size, and parallelism
                n = int(param_dict.get("n", 0))  # Default to 0 if missing
                r = int(param_dict.get("r", 0))
                p = int(param_dict.get("p", 0))

                # Validate parameters
                if not (n > 0 and r > 0 and p > 0):
                    raise ValueError("Scrypt parameters must be positive integers")

                # Decode salt and hash
                salt_b64 = parts[3]
                hash_hex = parts[4]

                salt = base64.urlsafe_b64decode(salt_b64)
                target_hash = bytes.fromhex(hash_hex)

                # Calculate lengths
                hash_length = len(target_hash)
                salt_length = len(salt)

                # Store all parameters in the list
                parameters.append({
                    "algorithm": algorithm,
                    "full_hash": hash_digest,
                    "n": n,
                    "r": r,
                    "p": p,
                    "hash_length": hash_length,
                    "salt_length": salt_length,
                    "salt": salt,
                    "target_hash": target_hash,
                })
            except (ValueError, KeyError) as e:
                raise ValueError(f"Error parsing Scrypt parameters: {hash_digest} - {e}")

        return parameters

    def log_parameters(self):
        first_entry = self.parameters[0]
        log_message = (
            f"hash length={first_entry['hash_length']}, "
            f"salt length={first_entry['salt_length']}, n={first_entry['n']}, "
            f"block size (r)={first_entry['r']}, parallelism={first_entry['p']}"
        )
        return log_message

    def verify(self, chunk):
        """
        Verifies a potential password by deriving its Scrypt hash
        and comparing it against each stored hash in target_hash_to_crack.
        """
        matches = {}
        for password in chunk:
            for entry in self.parameters:
                # Extract parameters for this hash
                n = entry["n"]
                r = entry["r"]
                p = entry["p"]
                hash_length = entry["hash_length"]
                salt = entry["salt"]
                target_hash = entry["target_hash"]

                # Instantiate a new Scrypt KDF
                scrypt_kdf = Scrypt(salt=salt, length=hash_length, n=n, r=r, p=p)
                try:
                    # Derive the hash for the potential password
                    computed_hash = scrypt_kdf.derive(password)

                    if computed_hash == target_hash:
                        matches[entry["full_hash"]] = self.decode_password(password)
                except Exception as e:
                    print(f"Error during verification: {e}")
                    continue  # Move to the next hash in case of an error

        return matches
