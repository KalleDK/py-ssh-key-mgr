import argon2

from ssh_key_mgr import b64
from ssh_key_mgr.encryption import (
    Argon2Params,
    ArgonID,
    SecretBytes,
)


def argon_type(aid: ArgonID):
    match aid:
        case ArgonID.D:
            return argon2.Type.D
        case ArgonID.I:
            return argon2.Type.I
        case ArgonID.ID:
            return argon2.Type.ID


def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes:
    hasher = argon2.PasswordHasher(
        time_cost=int(params.time_cost),
        memory_cost=int(params.memory_cost),
        parallelism=int(params.parallelism),
        hash_len=hash_size,
        salt_len=len(params.salt),
        type=argon_type(params.type),
    )
    hash_line = hasher.hash(passphrase.get_secret_value(), salt=params.salt)
    hash_passphrase = hash_line.split("$")[-1].encode()

    return b64.decode(hash_passphrase)


__all__ = ["hash_passphrase"]
