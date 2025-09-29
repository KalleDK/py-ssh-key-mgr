import abc
import dataclasses
from typing import ClassVar, Literal, SupportsBytes, override

from ssh_key_mgr.putty import ppk
from ssh_key_mgr.putty.checksum import MacKey
from ssh_key_mgr.putty.encryption import aes, argon
from ssh_key_mgr.putty.encryption.aes import (
    IV,
    CipherKey,
    EncryptedBytes,
)
from ssh_key_mgr.putty.encryption.argon import (
    Argon2Params,
    ArgonID,
    MemoryCost,
    Parallelism,
    Salt,
    TimeCost,
    gen_salt,
)
from ssh_key_mgr.putty.ppk.stream import HexField, IntField, StrField
from ssh_key_mgr.secretstr import SecretBytes

CIPHER_KEY_LENGTH = 32
CIPHER_IV_LENGTH = 16
MAC_KEY_LENGTH = 32
ARGON2_KEY_LENGTH = CIPHER_KEY_LENGTH + CIPHER_IV_LENGTH + MAC_KEY_LENGTH


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class DeriveKeyParams:
    argon2_type: ArgonID
    argon2_memory_cost: MemoryCost
    argon2_time_cost: TimeCost
    argon2_parallelism: Parallelism
    argon2_salt: Salt


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class DeriveAesKeyParams(DeriveKeyParams):
    aes_iv_length: int
    aes_cipher_length: int
    mac_length: int

    @property
    def hash_length(self) -> int:
        return self.aes_cipher_length + self.aes_iv_length + self.mac_length

    @classmethod
    def create(
        cls,
        argon2_type: ArgonID,
        argon2_memory_cost: MemoryCost,
        argon2_time_cost: TimeCost,
        argon2_parallelism: Parallelism,
        argon2_salt_length: int,
        aes_iv_length: int,
        aes_cipher_length: int,
        mac_length: int,
    ) -> "DeriveAesKeyParams":
        return cls(
            argon2_type=argon2_type,
            argon2_memory_cost=argon2_memory_cost,
            argon2_time_cost=argon2_time_cost,
            argon2_parallelism=argon2_parallelism,
            argon2_salt=gen_salt(argon2_salt_length),
            aes_iv_length=aes_iv_length,
            aes_cipher_length=aes_cipher_length,
            mac_length=mac_length,
        )


def slice(data: bytes, size: int) -> tuple[bytes, bytes]:
    return data[:size], data[size:]


def derive_key(params: DeriveKeyParams, hash_length: int, passphrase: SecretBytes) -> bytes:
    _params = argon.Argon2Params(
        type=params.argon2_type,
        memory_cost=params.argon2_memory_cost,
        time_cost=params.argon2_time_cost,
        parallelism=params.argon2_parallelism,
        salt=params.argon2_salt,
        hash_length=hash_length,
    )

    return argon.hash_passphrase(_params, passphrase)


def derive_aes_key(params: DeriveAesKeyParams, passphrase: SecretBytes) -> tuple[CipherKey, IV, MacKey]:
    key = derive_key(params, params.hash_length, passphrase)
    cipher_key, rest = slice(key, params.aes_cipher_length)
    iv, mac_key = slice(rest, params.aes_iv_length)
    return CipherKey(cipher_key), IV(iv), MacKey(mac_key)


def aes_decrypt(encrypted: EncryptedBytes, params: DeriveAesKeyParams, passphrase: SecretBytes) -> tuple[bytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(params, passphrase)

    decrypted = aes.decrypt(encrypted, cipher_key, iv)

    return decrypted, mac_key


def aes_encrypt(
    decrypted: SupportsBytes, params: DeriveAesKeyParams, passphrase: SecretBytes
) -> tuple[EncryptedBytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(params, passphrase)

    encrypted = aes.encrypt(bytes(decrypted), cipher_key, iv)

    return encrypted, mac_key


def add_padding(data: bytes, block_size: int) -> bytes:
    return data + aes.gen_padding(len(data), block_size=block_size)


# region Encryption


# region Encryption Base


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionParams:
    encryption_type: ClassVar[str]

    @abc.abstractmethod
    def encrypt(
        self, data: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, "DecryptionParams", MacKey]:
        raise NotImplementedError()

    @abc.abstractmethod
    def add_padding(self, data: SupportsBytes) -> bytes:
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class DecryptionParams:
    encryption_type: ClassVar[str]
    __child: ClassVar[dict[str, type["DecryptionParams"]]] = {}

    def __init_subclass__(cls) -> None:
        cls.__child[cls.encryption_type] = cls

    @classmethod
    @abc.abstractmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "DecryptionParams":
        if encryption_type not in cls.__child:
            raise ValueError(f"Unsupported encryption type {encryption_type}")
        return cls.__child[encryption_type].unmarshal_ppk_part(encryption_type, stream)

    @abc.abstractmethod
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        raise NotImplementedError()


# endregion

# region Encryption AES256_CBC
ENCRYPTION_AES256_CBC = "aes256-cbc"


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class AES256_CBC:
    BLOCK_SIZE: ClassVar[Literal[16]] = 16
    SALT_SIZE: ClassVar[Literal[16]] = 16
    CIPHER_KEY_LENGTH: ClassVar[Literal[32]] = 32
    CIPHER_IV_LENGTH: ClassVar[Literal[16]] = 16
    MAC_KEY_LENGTH: ClassVar[Literal[32]] = 32


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionParams_AES256_CBC(EncryptionParams, AES256_CBC):
    encryption_type: ClassVar[str] = ENCRYPTION_AES256_CBC
    key_derivation: ArgonID = ArgonID.ID
    argon2_memory: MemoryCost = MemoryCost(8192)
    argon2_passes: TimeCost = TimeCost(21)
    argon2_parallelism: Parallelism = Parallelism(1)

    @override
    def add_padding(self, data: SupportsBytes) -> bytes:
        return add_padding(bytes(data), block_size=self.BLOCK_SIZE)

    @override
    def encrypt(
        self, data: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, "DecryptionParams_AES256_CBC", MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for encryption with {ENCRYPTION_AES256_CBC}")
        derive_key_params = self.as_derive_aes_key_params()
        encrypted, mac_key = aes_encrypt(
            data,
            derive_key_params,
            passphrase,
        )
        return (
            encrypted,
            DecryptionParams_AES256_CBC(
                key_derivation=self.key_derivation,
                argon2_memory=self.argon2_memory,
                argon2_passes=self.argon2_passes,
                argon2_parallelism=self.argon2_parallelism,
                argon2_salt=derive_key_params.argon2_salt,
            ),
            mac_key,
        )

    def as_derive_aes_key_params(self) -> DeriveAesKeyParams:
        return DeriveAesKeyParams.create(
            argon2_type=self.key_derivation,
            argon2_memory_cost=self.argon2_memory,
            argon2_time_cost=self.argon2_passes,
            argon2_parallelism=self.argon2_parallelism,
            argon2_salt_length=self.SALT_SIZE,
            aes_iv_length=self.CIPHER_IV_LENGTH,
            aes_cipher_length=self.CIPHER_KEY_LENGTH,
            mac_length=self.MAC_KEY_LENGTH,
        )


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class DecryptionParams_AES256_CBC(DecryptionParams, AES256_CBC):
    encryption_type: ClassVar[str] = ENCRYPTION_AES256_CBC
    key_derivation: ArgonID
    argon2_memory: MemoryCost
    argon2_passes: TimeCost
    argon2_parallelism: Parallelism
    argon2_salt: Salt

    def as_derive_aes_key_params(self) -> DeriveAesKeyParams:
        return DeriveAesKeyParams(
            argon2_type=self.key_derivation,
            argon2_memory_cost=self.argon2_memory,
            argon2_time_cost=self.argon2_passes,
            argon2_parallelism=self.argon2_parallelism,
            argon2_salt=self.argon2_salt,
            aes_iv_length=self.CIPHER_IV_LENGTH,
            aes_cipher_length=self.CIPHER_KEY_LENGTH,
            mac_length=self.MAC_KEY_LENGTH,
        )

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "DecryptionParams_AES256_CBC":
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")
        key_derivation = ArgonID(stream.read_named_str("Key-Derivation"))
        argon2_memory = MemoryCost(stream.read_named_int("Argon2-Memory"))
        argon2_passes = TimeCost(stream.read_named_int("Argon2-Passes"))
        argon2_parallelism = Parallelism(stream.read_named_int("Argon2-Parallelism"))
        argon2_salt = Salt(stream.read_named_hexbytes("Argon2-Salt"))
        return DecryptionParams_AES256_CBC(
            key_derivation=key_derivation,
            argon2_memory=argon2_memory,
            argon2_passes=argon2_passes,
            argon2_parallelism=argon2_parallelism,
            argon2_salt=argon2_salt,
        )

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        stream.write_str(StrField(name="Key-Derivation", value=self.key_derivation.value))
        stream.write_int(IntField(name="Argon2-Memory", value=int(self.argon2_memory)))
        stream.write_int(IntField(name="Argon2-Passes", value=int(self.argon2_passes)))
        stream.write_int(IntField(name="Argon2-Parallelism", value=int(self.argon2_parallelism)))
        stream.write_hexbytes(HexField(name="Argon2-Salt", value=self.argon2_salt.value))

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for decryption of {self.encryption_type}")

        return aes_decrypt(data, self.as_derive_aes_key_params(), passphrase)


# endregion

# region Encryption NONE

ENCRYPTION_NONE = "none"


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionParams_NONE(EncryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NONE

    @override
    def add_padding(self, data: SupportsBytes) -> bytes:
        return bytes(data)

    @override
    def encrypt(
        self, data: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, "DecryptionParams_NONE", MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for encryption with {ENCRYPTION_NONE}")
        return EncryptedBytes(bytes(data)), DecryptionParams_NONE(), MacKey(b"")


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class DecryptionParams_NONE(DecryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NONE

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "DecryptionParams_NONE":
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")
        return DecryptionParams_NONE()

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for decryption of {self.encryption_type}")
        return bytes(data), MacKey(b"")

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        pass


# endregion

# endregion


__all__ = [
    "aes_decrypt",
    "aes_encrypt",
    "IV",
    "CipherKey",
    "EncryptedBytes",
    "Argon2Params",
    "ArgonID",
    "MemoryCost",
    "Parallelism",
    "Salt",
    "TimeCost",
]
