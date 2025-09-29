import abc
import dataclasses
from typing import ClassVar, Self, SupportsBytes, cast

from ssh_key_mgr.encryption import (
    EncryptedBytes,
    SecretBytes,
    gen_random_padding,
)
from ssh_key_mgr.putty import ppk
from ssh_key_mgr.putty.checksum import MacKey

# region Encryption Base


def add_padding(data: bytes, block_size: int) -> bytes:
    return data + gen_random_padding(len(data), block_size=block_size)


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class DecryptionParams:
    encryption_type: ClassVar[str]
    __child: ClassVar[dict[str, type["DecryptionParams"]]] = {}

    def __init_subclass__(cls) -> None:
        cls.__child[cls.encryption_type] = cls

    @property
    @abc.abstractmethod
    def require_passphrase(self) -> bool:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> Self:
        if encryption_type not in cls.__child:
            raise ValueError(f"Unsupported encryption type {encryption_type}")
        return cast(Self, cls.__child[encryption_type].unmarshal_ppk_part(encryption_type, stream))

    @abc.abstractmethod
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        raise NotImplementedError()


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionParams:
    encryption_type: ClassVar[str]

    @property
    @abc.abstractmethod
    def require_passphrase(self) -> bool:
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(
        self, decrypted: bytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, DecryptionParams, MacKey]:
        raise NotImplementedError()

    def encrypt(
        self, data: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, DecryptionParams, MacKey, bytes]:
        data = bytes(data)
        padded_data = add_padding(data, self.block_size)
        encrypted, decryption_params, mac_key = self._encrypt(padded_data, passphrase)
        return (
            encrypted,
            decryption_params,
            mac_key,
            padded_data,
        )


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption:
    encryption_type: ClassVar[str]

    @property
    @abc.abstractmethod
    def require_passphrase(self) -> bool:
        raise NotImplementedError()

    @abc.abstractmethod
    def generate_params(self) -> "EncryptionParams":
        raise NotImplementedError()


# endregion
