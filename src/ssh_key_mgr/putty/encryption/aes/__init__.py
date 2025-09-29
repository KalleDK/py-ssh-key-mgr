import typing

from ssh_key_mgr.encryption import (
    IV,
    CipherKey,
    EncryptedBytes,
)

if typing.TYPE_CHECKING:

    def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes: ...
    def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes: ...
else:
    try:
        from .impl import decrypt as decrypt
        from .impl import encrypt as encrypt

    except ImportError:

        def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes:
            raise ImportError("PyCryptodome is required for AES decryption/encryption")

        def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes:
            raise ImportError("PyCryptodome is required for AES decryption/encryption")


__all__ = ["decrypt", "encrypt"]
