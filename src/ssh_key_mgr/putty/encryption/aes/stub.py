from ssh_key_mgr.encryption import (
    IV,
    CipherKey,
    EncryptedBytes,
)


def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes:
    raise ImportError("PyCryptodome is required for AES decryption/encryption")


def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes:
    raise ImportError("PyCryptodome is required for AES decryption/encryption")
