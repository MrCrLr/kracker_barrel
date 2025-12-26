from importlib import import_module


HANDLER_IMPORTS = {
    "argon": ("core.hash_handlers.argon2", "Argon2Handler"),
    "scrypt": ("core.hash_handlers.scrypt", "ScryptHandler"),
    "pbkdf2": ("core.hash_handlers.pbkdf2", "PBKDF2Handler"),
    "bcrypt": ("core.hash_handlers.bcrypt", "BcryptHandler"),
    "ntlm": ("core.hash_handlers.ntlm", "NTLMHandler"),
    "md5": ("core.hash_handlers.md5", "MD5Handler"),
    "sha256": ("core.hash_handlers.sha256", "SHA256Handler"),
    "sha512": ("core.hash_handlers.sha512", "SHA512Handler"),
}


def get_handler(hash_type, hash_digest_with_metadata):
    try:
        module_name, class_name = HANDLER_IMPORTS[hash_type]
    except KeyError:
        raise ValueError(
            f"No handler available for hash type: {hash_type}. Supported types: {', '.join(HANDLER_IMPORTS.keys())}"
        )

    module = import_module(module_name)
    handler_cls = getattr(module, class_name)
    return handler_cls(hash_digest_with_metadata)
