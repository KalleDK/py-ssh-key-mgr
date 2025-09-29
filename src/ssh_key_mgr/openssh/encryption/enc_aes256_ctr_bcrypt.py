import dataclasses
from typing import Annotated, ClassVar, override

import ssh_proto_types as spt

from ssh_key_mgr.encryption import IV, CipherKey, EncryptedBytes, Rounds, Salt, SecretBytes, gen_salt
from ssh_key_mgr.openssh.encryption import aes as aes
from ssh_key_mgr.openssh.encryption import bcrypt as bc
from ssh_key_mgr.openssh.encryption.base import DecryptionParams, Encryption, EncryptionParams


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AESParams:
    block_size: int
    cipher_key_length: int
    cipher_iv_length: int

    @property
    def hash_size(self) -> int:
        return self.cipher_key_length + self.cipher_iv_length


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class BCryptParams:
    rounds: Rounds
    salt: Salt


def slice(data: bytes, size: int) -> tuple[bytes, bytes]:
    return data[:size], data[size:]


def derive_aes_key(bcrypt_params: BCryptParams, aes_params: AESParams, passphrase: SecretBytes) -> tuple[CipherKey, IV]:
    hash = bc.hash_passphrase(passphrase, aes_params.hash_size, bcrypt_params.rounds, bcrypt_params.salt)
    cipher_key, iv = slice(hash, aes_params.cipher_key_length)
    return CipherKey(cipher_key), IV(iv)


def aes_decrypt(
    encrypted: aes.EncryptedBytes,
    bcrypt_params: BCryptParams,
    aes_params: AESParams,
    passphrase: SecretBytes,
) -> bytes:
    key, iv = derive_aes_key(bcrypt_params, aes_params, passphrase)
    decrypted = aes.decrypt(encrypted, key, iv)
    return decrypted


def aes_encrypt(
    decrypted: bytes,
    bcrypt_params: BCryptParams,
    aes_params: AESParams,
    passphrase: SecretBytes,
) -> aes.EncryptedBytes:
    key, iv = derive_aes_key(bcrypt_params, aes_params, passphrase)
    encrypted = aes.encrypt(decrypted, key, iv)
    return encrypted


ENCRYPTION_AES256_CTR = "aes256-ctr"
KDEF_BCRYPT = "bcrypt"

BLOCK_SIZE = 16
SALT_SIZE = 16
IV_SIZE = 16
CIPHER_KEY_SIZE = 32
AES256_PARAMS = AESParams(block_size=BLOCK_SIZE, cipher_key_length=CIPHER_KEY_SIZE, cipher_iv_length=IV_SIZE)

DEFAULT_ROUNDS = Rounds(24)


class KDFOptions(spt.Packet):
    salt: Annotated[Salt, bytes]
    rounds: Annotated[Rounds, spt.c_uint32]


class DecryptionParamsAes256(DecryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_AES256_CTR
    kdf_name: ClassVar[str] = KDEF_BCRYPT
    kdf_opts: Annotated[KDFOptions, spt.nested]

    @property
    @override
    def require_passphrase(self) -> bool:
        return True

    @property
    @override
    def block_size(self) -> int:
        return AES256_PARAMS.block_size

    @override
    def _decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> bytes:
        if passphrase is None:
            raise ValueError("Passphrase is required for encrypted private key")
        return aes_decrypt(
            encrypted,
            bcrypt_params=BCryptParams(
                rounds=self.kdf_opts.rounds,
                salt=self.kdf_opts.salt,
            ),
            aes_params=AES256_PARAMS,
            passphrase=passphrase,
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class EncryptionParamsAes256(EncryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_AES256_CTR
    bcrypt_params: BCryptParams

    @property
    @override
    def block_size(self) -> int:
        return AES256_PARAMS.block_size

    @override
    def _encrypt(self, decrypted: bytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, DecryptionParams]:
        if passphrase is None:
            raise ValueError("Passphrase is required for encrypted private key")

        encrypted = aes_encrypt(
            decrypted,
            bcrypt_params=self.bcrypt_params,
            aes_params=AES256_PARAMS,
            passphrase=passphrase,
        )

        return encrypted, DecryptionParamsAes256(
            kdf_opts=KDFOptions(
                salt=self.bcrypt_params.salt,
                rounds=self.bcrypt_params.rounds,
            )
        )


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionAes256(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_AES256_CTR
    salt_size: ClassVar[int] = SALT_SIZE
    rounds: Rounds = DEFAULT_ROUNDS

    @override
    def generate_params(self) -> EncryptionParamsAes256:
        return EncryptionParamsAes256(bcrypt_params=BCryptParams(rounds=self.rounds, salt=gen_salt(self.salt_size)))
