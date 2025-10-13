import typing

from ssh_key_mgr.encryption import Argon2Params, SecretBytes

if typing.TYPE_CHECKING:

    def hash_passphrase(params: Argon2Params, hash_size: int, passphrase: SecretBytes) -> bytes: ...

else:
    try:
        from .impl import hash_passphrase as hash_passphrase

    except ImportError:
        from .stub import hash_passphrase as hash_passphrase


__all__ = [
    "hash_passphrase",
]
