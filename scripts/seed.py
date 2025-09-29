from typing import TypedDict

from ssh_key_mgr import putty
from ssh_key_mgr.encryption import (
    IV,
    Argon2Params,
    CipherKey,
    EncryptedBytes,
    SecretBytes,
)
from ssh_key_mgr.putty.keys import (
    PuttyPublicKey,
)


class AesTestVectorT(TypedDict):
    CipherKey: CipherKey
    IV: IV
    Decrypted: bytes
    Encrypted: EncryptedBytes


class AES_TESTS_DICT(TypedDict):
    CipherKey: CipherKey
    IV: IV
    Decrypted: bytes
    Encrypted: EncryptedBytes


PUTTY_AES: dict[str, AES_TESTS_DICT] = {}


class PUTTY_ARGON_DICT(TypedDict):
    Params: Argon2Params
    Passphrase: SecretBytes
    Hash: bytes
    HashLength: int


PUTTY_ARGON: dict[str, PUTTY_ARGON_DICT] = {}

PUTTY_PUBLIC_KEYS: dict[str, PuttyPublicKey] = {}

PUTTY_PUBLIC_KEY_WIRES: dict[str, bytes] = {}

PUTTY_PRIVATE_KEY_WIRES: dict[str, bytes] = {}

PUTTY_KEY_NAMES: list[str] = []

PUTTY_ENC_NAMES: list[str] = ["NONE", "AES256_CBC"]


class PuttyKeyEncryptionDict(TypedDict):
    Params: putty.Encryption
    Passphrase: SecretBytes | None
    FileObj: putty.PuttyFileV3
    File: str


class PuttyKeyTestDict(TypedDict):
    Encryptions: dict[str, PuttyKeyEncryptionDict]


PUTTY_KEY_TESTS: dict[str, PuttyKeyTestDict] = {}
