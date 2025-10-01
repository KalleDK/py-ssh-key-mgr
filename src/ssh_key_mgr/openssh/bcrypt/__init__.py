import typing

from ssh_key_mgr.openssh.bcrypt.base import (
    Rounds,
    Salt,
)
from ssh_key_mgr.secretstr import SecretBytes

if typing.TYPE_CHECKING:

    def gen_salt(size: int) -> Salt: ...
    def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes: ...
else:
    try:
        from ssh_key_mgr.openssh.bcrypt.impl import gen_salt as gen_salt
        from ssh_key_mgr.openssh.bcrypt.impl import hash_passphrase as hash_passphrase

    except ImportError:  # pragma: no cover

        def gen_salt(size: int) -> Salt:
            raise ImportError("argon2-cffi is required for Argon2 key derivation")

        def hash_passphrase(passphrase: SecretBytes, hash_len: int, rounds: Rounds, salt: Salt) -> bytes:
            raise ImportError("argon2-cffi is required for Argon2 key derivation")


__all__ = ["hash_passphrase", "gen_salt", "Rounds", "Salt"]
