from ssh_key_mgr.encryption import Argon2Params, SecretBytes


def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes:
    raise ImportError("argon2-cffi is required for Argon2 hashing")
