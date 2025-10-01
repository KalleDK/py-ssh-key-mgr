import bcrypt

from ssh_key_mgr.openssh.bcrypt.base import MAX_SALT_SIZE, Rounds, Salt
from ssh_key_mgr.secretstr import SecretBytes


def gen_salt(size: int) -> Salt:
    assert size <= MAX_SALT_SIZE, f"SALT_SIZE must be <= {MAX_SALT_SIZE}"
    assert size > 0, "SALT_SIZE must be > 0"
    _, salt = bcrypt.gensalt(prefix=b"2b", rounds=12).rsplit(b"$", 1)
    return Salt(salt[:size])


def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes:
    return bcrypt.kdf(
        password=passphrase.get_secret_value(),
        salt=bytes(salt),
        desired_key_bytes=hash_len,
        rounds=int(rounds),
        ignore_few_rounds=True,
    )
