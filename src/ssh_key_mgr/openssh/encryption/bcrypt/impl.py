import bcrypt

from ssh_key_mgr.encryption import Rounds, Salt, SecretBytes


def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes:
    return bcrypt.kdf(
        password=passphrase.get_secret_value(),
        salt=bytes(salt),
        desired_key_bytes=hash_len,
        rounds=int(rounds),
        ignore_few_rounds=True,
    )
