from ssh_key_mgr.encryption import (
    IV,
    CipherKey,
    EncryptedBytes,
    Nonce,
)


def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV, *, nonce: Nonce | None = None) -> bytes:
    raise ImportError("pycryptodome is required for AES decryption")


def encrypt(decrypted: bytes, key: CipherKey, iv: IV, *, nonce: Nonce | None = None) -> EncryptedBytes:
    raise ImportError("pycryptodome is required for AES encryption")
