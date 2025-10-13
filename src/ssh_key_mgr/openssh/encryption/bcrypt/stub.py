from ssh_key_mgr.encryption import Rounds, Salt, SecretBytes


def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes:
    raise ImportError("argon2-cffi is required for Argon2 key derivation")
