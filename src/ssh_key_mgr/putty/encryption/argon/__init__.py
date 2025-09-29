import typing

from ssh_key_mgr.encryption import Argon2Params, SecretBytes

if typing.TYPE_CHECKING:

    def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes: ...

else:
    try:
        from .impl import hash_passphrase as hash_passphrase

    except ImportError:

        def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes:
            raise ImportError("argon2-cffi is required for Argon2 hashing")


__all__ = [
    "hash_passphrase",
]
