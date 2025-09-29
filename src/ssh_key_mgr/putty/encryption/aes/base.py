import dataclasses
from typing import Self

from ssh_key_mgr.secretstr import SecretBytes


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _bytes:
    value: bytes

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)

    @classmethod
    def fromhex(cls, v: str) -> Self:
        return cls(bytes.fromhex(v))


class EncryptedBytes(_bytes):
    pass


class IV(SecretBytes):
    @classmethod
    def fromhex(cls, v: str) -> Self:
        return cls(bytes.fromhex(v))


class CipherKey(SecretBytes):
    @classmethod
    def fromhex(cls, v: str) -> Self:
        return cls(bytes.fromhex(v))
