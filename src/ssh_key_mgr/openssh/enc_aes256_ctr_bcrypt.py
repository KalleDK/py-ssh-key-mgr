from ssh_key_mgr.openssh import aes
from ssh_key_mgr.openssh import bcrypt as bc
from ssh_key_mgr.secretstr import SecretBytes

SALT_SIZE = 16
BLOCK_SIZE = 16

IV_LENGTH = 16
CIPHER_KEY_LENGTH = 32
HASH_LENGTH = IV_LENGTH + CIPHER_KEY_LENGTH

DEFAULT_ROUNDS = bc.Rounds(24)


def get_key_parts(
    passphrase: SecretBytes, rounds: bc.Rounds | None = None, salt: bc.Salt | None = None
) -> tuple[aes.CipherKey, aes.IV]:
    rounds = rounds if rounds is not None else DEFAULT_ROUNDS
    salt = salt if salt is not None else bc.gen_salt(SALT_SIZE)
    hash = bc.hash_passphrase(passphrase, HASH_LENGTH, rounds, salt)
    key = aes.CipherKey(hash[:CIPHER_KEY_LENGTH])
    iv = aes.IV(hash[CIPHER_KEY_LENGTH : CIPHER_KEY_LENGTH + IV_LENGTH])
    return key, iv


def decrypt(
    encrypted: aes.EncryptedBytes,
    passphrase: SecretBytes,
    rounds: bc.Rounds,
    salt: bc.Salt,
) -> bytes:
    key, iv = get_key_parts(passphrase, rounds, salt)
    decrypted = aes.decrypt(encrypted, key, iv)
    return decrypted


def encrypt(
    decrypted: bytes,
    passphrase: SecretBytes,
    rounds: bc.Rounds | None = None,
    salt: bc.Salt | None = None,
) -> aes.EncryptedBytes:
    key, iv = get_key_parts(passphrase, rounds, salt)
    encrypted = aes.encrypt(decrypted, key, iv)
    return encrypted
