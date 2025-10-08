import abc
import dataclasses
from typing import ClassVar, Literal, NamedTuple, Self, SupportsBytes, override

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


class AESParams(NamedTuple):
    block_size: int
    cipher_key_length: int
    cipher_iv_length: int
    mac_key_length: int

    @property
    def hash_size(self) -> int:
        return self.cipher_key_length + self.cipher_iv_length + self.mac_key_length


def slice(data: bytes, size: int) -> tuple[bytes, bytes]:
    return data[:size], data[size:]


def derive_aes_key(
    argon_params: argon.Argon2Params, aes_params: "AESParams", passphrase: SecretBytes
) -> tuple[CipherKey, IV, MacKey]:
    key = argon.hash_passphrase(argon_params, aes_params.hash_size, passphrase)
    cipher_key, rest = slice(key, aes_params.cipher_key_length)
    iv, mac_key = slice(rest, aes_params.cipher_iv_length)
    return CipherKey(cipher_key), IV(iv), MacKey(mac_key)


def aes_decrypt(
    encrypted: EncryptedBytes, argon_params: argon.Argon2Params, aes_params: "AESParams", passphrase: SecretBytes
) -> tuple[bytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(argon_params, aes_params, passphrase)

    decrypted = aes.decrypt(encrypted, cipher_key, iv)

    return decrypted, mac_key


def aes_encrypt(
    decrypted: SupportsBytes, argon_params: argon.Argon2Params, aes_params: "AESParams", passphrase: SecretBytes
) -> tuple[EncryptedBytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(argon_params, aes_params, passphrase)

    encrypted = aes.encrypt(bytes(decrypted), cipher_key, iv)

    return encrypted, mac_key


def add_padding(data: bytes, block_size: int) -> bytes:
    return data + aes.gen_padding(len(data), block_size=block_size)


# region Encryption


# region Encryption Base


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption:
    encryption_type: ClassVar[str]

    @abc.abstractmethod
    def generate_params(self) -> "EncryptionParams":
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionParams:
    encryption_type: ClassVar[str]
    __child: ClassVar[dict[str, type["EncryptionParams"]]] = {}

    def __init_subclass__(cls) -> None:
        cls.__child[cls.encryption_type] = cls

    @classmethod
    @abc.abstractmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "EncryptionParams":
        if encryption_type not in cls.__child:
            raise ValueError(f"Unsupported encryption type {encryption_type}")
        return cls.__child[encryption_type].unmarshal_ppk_part(encryption_type, stream)

    @abc.abstractmethod
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        raise NotImplementedError()

    @abc.abstractmethod
    def encrypt(self, data: SupportsBytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, MacKey]:
        raise NotImplementedError()

    @abc.abstractmethod
    def add_padding(self, data: SupportsBytes) -> bytes:
        raise NotImplementedError()


# endregion

# region Encryption AES256_CBC
ENCRYPTION_AES256_CBC = "aes256-cbc"


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_AES256_CBC(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_AES256_CBC
    salt_size: ClassVar[Literal[16]] = 16

    key_derivation: ArgonID = ArgonID.ID
    argon2_memory: MemoryCost = MemoryCost(8192)
    argon2_passes: TimeCost = TimeCost(21)
    argon2_parallelism: Parallelism = Parallelism(1)

    @override
    def generate_params(self) -> "Encryption_AES256_CBC_Params":
        salt = gen_salt(self.salt_size)
        return Encryption_AES256_CBC_Params(
            argon2_params=argon.Argon2Params(
                type=self.key_derivation,
                memory_cost=self.argon2_memory,
                time_cost=self.argon2_passes,
                parallelism=self.argon2_parallelism,
                salt=salt,
            )
        )


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_AES256_CBC_Params(EncryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_AES256_CBC
    aes_params: ClassVar[AESParams] = AESParams(
        block_size=16,
        cipher_key_length=32,
        cipher_iv_length=16,
        mac_key_length=32,
    )
    argon2_params: argon.Argon2Params

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> Self:
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")

        key_derivation = ArgonID(stream.read_named_str("Key-Derivation"))
        argon2_memory = MemoryCost(stream.read_named_int("Argon2-Memory"))
        argon2_passes = TimeCost(stream.read_named_int("Argon2-Passes"))
        argon2_parallelism = Parallelism(stream.read_named_int("Argon2-Parallelism"))
        argon2_salt = Salt(stream.read_named_hexbytes("Argon2-Salt"))

        return cls(
            argon2_params=argon.Argon2Params(
                type=key_derivation,
                memory_cost=argon2_memory,
                time_cost=argon2_passes,
                parallelism=argon2_parallelism,
                salt=argon2_salt,
            )
        )

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        stream.write_str(StrField(name="Key-Derivation", value=self.argon2_params.type.value))
        stream.write_int(IntField(name="Argon2-Memory", value=int(self.argon2_params.memory_cost)))
        stream.write_int(IntField(name="Argon2-Passes", value=int(self.argon2_params.time_cost)))
        stream.write_int(IntField(name="Argon2-Parallelism", value=int(self.argon2_params.parallelism)))
        stream.write_hexbytes(HexField(name="Argon2-Salt", value=bytes(self.argon2_params.salt)))

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for decryption of {self.encryption_type}")

        return aes_decrypt(data, self.argon2_params, self.aes_params, passphrase)

    @override
    def add_padding(self, data: SupportsBytes) -> bytes:
        return add_padding(bytes(data), block_size=self.aes_params.block_size)

    @override
    def encrypt(self, data: SupportsBytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for encryption with {ENCRYPTION_AES256_CBC}")

        encrypted, mac_key = aes_encrypt(
            data,
            self.argon2_params,
            self.aes_params,
            passphrase,
        )
        return (
            encrypted,
            mac_key,
        )


# endregion

# region Encryption NONE

ENCRYPTION_NONE = "none"


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_NONE(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_NONE

    @override
    def generate_params(self) -> "Encryption_NONE_Params":
        return Encryption_NONE_Params()


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_NONE_Params(EncryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NONE

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "Encryption_NONE_Params":
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")
        return Encryption_NONE_Params()

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for decryption of {self.encryption_type}")
        return bytes(data), MacKey(b"")

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        pass

    @override
    def add_padding(self, data: SupportsBytes) -> bytes:
        return bytes(data)

    @override
    def encrypt(self, data: SupportsBytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for encryption with {ENCRYPTION_NONE}")
        return EncryptedBytes(bytes(data)), MacKey(b"")


# endregion

# endregion


__all__ = [
    "Encryption",
    "Encryption_AES256_CBC",
    "Encryption_NONE",
    "EncryptionParams",
    "Encryption_AES256_CBC_Params",
    "Encryption_NONE_Params",
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
