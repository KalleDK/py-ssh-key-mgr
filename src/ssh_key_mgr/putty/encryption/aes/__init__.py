import random
import typing

from ssh_key_mgr.putty.encryption.aes.base import (
    IV,
    CipherKey,
    EncryptedBytes,
)


def gen_padding(size: int, block_size: int = 16) -> bytes:
    pad_len = (block_size - (size % block_size)) % block_size
    return random.randbytes(pad_len)


if typing.TYPE_CHECKING:

    def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes: ...
    def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes: ...
else:
    try:
        from ssh_key_mgr.putty.encryption.aes.impl import decrypt as decrypt
        from ssh_key_mgr.putty.encryption.aes.impl import encrypt as encrypt

    except ImportError:

        def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes:
            raise ImportError("PyCryptodome is required for AES decryption/encryption")

        def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes:
            raise ImportError("PyCryptodome is required for AES decryption/encryption")


__all__ = [
    "IV",
    "CipherKey",
    "EncryptedBytes",
    "decrypt",
    "encrypt",
]
