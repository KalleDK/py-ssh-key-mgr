from Crypto.Cipher import AES

from ssh_key_mgr.encryption import IV, CipherKey, EncryptedBytes


def decrypt(encrypted: EncryptedBytes, key: CipherKey, iv: IV) -> bytes:
    cipher = AES.new(  # type: ignore
        key.get_secret_value(), AES.MODE_CBC, iv=iv.get_secret_value()
    )
    return cipher.decrypt(bytes(encrypted))


def encrypt(decrypted: bytes, key: CipherKey, iv: IV) -> EncryptedBytes:
    cipher = AES.new(  # type: ignore
        key.get_secret_value(), AES.MODE_CBC, iv=iv.get_secret_value()
    )
    return EncryptedBytes(cipher.encrypt(decrypted))
