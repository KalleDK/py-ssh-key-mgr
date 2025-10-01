import typing

from ssh_key_mgr.openssh.aes.base import (
    IV,
    CipherKey,
    EncryptedBytes,
    Nonce,
)

if typing.TYPE_CHECKING:

    def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV, *, nonce: Nonce = ...) -> bytes: ...
    def encrypt(decrypted: bytes, key: CipherKey, iv: IV, *, nonce: Nonce = Nonce(b"")) -> EncryptedBytes: ...
else:
    try:
        from ssh_key_mgr.openssh.aes.impl import decrypt as decrypt
        from ssh_key_mgr.openssh.aes.impl import encrypt as encrypt

    except ImportError:  # pragma: no cover

        def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV, *, nonce: Nonce = Nonce(b"")) -> bytes:
            raise ImportError("pycryptodome is required for AES decryption")

        def encrypt(decrypted: bytes, key: CipherKey, iv: IV, *, nonce: Nonce = Nonce(b"")) -> EncryptedBytes:
            raise ImportError("pycryptodome is required for AES encryption")


__all__ = [
    "IV",
    "CipherKey",
    "EncryptedBytes",
    "Nonce",
    "decrypt",
    "encrypt",
]
