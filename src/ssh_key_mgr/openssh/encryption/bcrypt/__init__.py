import typing

from ssh_key_mgr.encryption import Rounds, Salt, SecretBytes

if typing.TYPE_CHECKING:

    def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes: ...
else:
    try:
        from .impl import hash_passphrase as hash_passphrase

    except ImportError:  # pragma: no cover

        def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes:
            raise ImportError("argon2-cffi is required for Argon2 key derivation")


__all__ = ["hash_passphrase"]
