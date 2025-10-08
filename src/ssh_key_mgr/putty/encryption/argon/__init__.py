import typing

from ssh_key_mgr.putty.encryption.argon.base import (
    Argon2Params,
    ArgonID,
    MemoryCost,
    Parallelism,
    Salt,
    TimeCost,
)
from ssh_key_mgr.secretstr import SecretBytes

if typing.TYPE_CHECKING:

    def gen_salt(length: int) -> Salt: ...
    def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes: ...

else:
    try:
        from ssh_key_mgr.putty.encryption.argon.impl import gen_salt as gen_salt
        from ssh_key_mgr.putty.encryption.argon.impl import hash_passphrase as hash_passphrase

    except ImportError:

        def gen_salt(length: int) -> Salt:
            raise ImportError("argon2-cffi is required for Argon2 salt generation")

        def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes:
            raise ImportError("argon2-cffi is required for Argon2 hashing")


__all__ = [
    "Argon2Params",
    "ArgonID",
    "Salt",
    "MemoryCost",
    "Parallelism",
    "TimeCost",
    "hash_passphrase",
    "gen_salt",
]
