from Crypto.Cipher import AES

from ssh_key_mgr.openssh.aes.base import IV, CipherKey, EncryptedBytes, Nonce


def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV, *, nonce: Nonce | None = None) -> bytes:
    nonce = nonce if nonce is not None else Nonce(b"")
    cipher = AES.new(  # type: ignore
        key.get_secret_value(), AES.MODE_CTR, initial_value=iv.get_secret_value(), nonce=nonce.get_secret_value()
    )
    return cipher.decrypt(bytes(encrypted))


def encrypt(decrypted: bytes, key: CipherKey, iv: IV, *, nonce: Nonce | None = None) -> EncryptedBytes:
    nonce = nonce if nonce is not None else Nonce(b"")
    cipher = AES.new(  # type: ignore
        key.get_secret_value(), AES.MODE_CTR, initial_value=iv.get_secret_value(), nonce=nonce.get_secret_value()
    )
    return EncryptedBytes(cipher.encrypt(decrypted))
