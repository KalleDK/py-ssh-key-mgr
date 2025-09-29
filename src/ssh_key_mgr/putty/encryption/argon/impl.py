import base64
import random

import argon2

from ssh_key_mgr.putty.encryption.argon.base import (
    Argon2Params,
    ArgonID,
    Salt,
)
from ssh_key_mgr.secretstr import SecretBytes


def gen_salt(length: int) -> Salt:
    return Salt(random.randbytes(length))


def argon_type(aid: ArgonID):
    match aid:
        case ArgonID.D:
            return argon2.Type.D
        case ArgonID.I:
            return argon2.Type.I
        case ArgonID.ID:
            return argon2.Type.ID


def hash_passphrase(params: Argon2Params, passphrase: SecretBytes) -> bytes:
    hasher = argon2.PasswordHasher(
        time_cost=int(params.time_cost),
        memory_cost=int(params.memory_cost),
        parallelism=int(params.parallelism),
        hash_len=params.hash_length,
        salt_len=len(params.salt),
        type=argon_type(params.type),
    )
    hash_line = hasher.hash(passphrase.get_secret_value(), salt=params.salt.value)
    hash_passphrase = hash_line.split("$")[-1].encode()
    key = base64.b64decode(hash_passphrase + b"=" * (-len(hash_passphrase) % 4))
    return key
