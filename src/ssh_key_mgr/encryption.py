import dataclasses
import enum
import random
import struct
from typing import Any, NewType, Self


class _SecretBase[T]:
    def __init__(self, secret_value: T) -> None:
        self._secret_value: T = secret_value

    def get_secret_value(self) -> T:
        """Get the secret value.

        Returns:
            The secret value.
        """
        return self._secret_value

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, self.__class__) and self.get_secret_value() == other.get_secret_value()

    def __hash__(self) -> int:
        return hash(self.get_secret_value())

    def __str__(self) -> str:
        return str(self._display())

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self._display()!r})"

    def _display(self) -> str | bytes:
        raise NotImplementedError  # pragma: no cover


class SecretStr(_SecretBase[str]):
    def __len__(self) -> int:
        return len(self._secret_value)

    def _display(self) -> str:
        return "**********" if self._secret_value else ""


class SecretBytes(_SecretBase[bytes]):
    def __len__(self) -> int:
        return len(self._secret_value)

    def _display(self) -> str:
        return "b'**********'" if self._secret_value else "b''"


class IV(SecretBytes):
    @classmethod
    def fromhex(cls, v: str) -> Self:
        return cls(bytes.fromhex(v))


class CipherKey(SecretBytes):
    @classmethod
    def fromhex(cls, v: str) -> Self:
        return cls(bytes.fromhex(v))


class Nonce(SecretBytes):
    pass


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


Salt = NewType("Salt", bytes)
MemoryCost = NewType("MemoryCost", int)
TimeCost = NewType("TimeCost", int)
Parallelism = NewType("Parallelism", int)
Rounds = NewType("Rounds", int)


class ArgonID(enum.StrEnum):
    D = "Argon2d"
    I = "Argon2i"  # noqa: E741
    ID = "Argon2id"


@dataclasses.dataclass(frozen=True, slots=True, eq=True, kw_only=True)
class Argon2Params:
    type: ArgonID
    memory_cost: MemoryCost
    time_cost: TimeCost
    parallelism: Parallelism
    salt: Salt


def randbytes(n: int) -> bytes:
    return random.randbytes(n)


def gen_salt(length: int) -> Salt:
    return Salt(randbytes(length))


def gen_random_padding(size: int, block_size: int = 16) -> bytes:
    pad_len = (block_size - (size % block_size)) % block_size
    return randbytes(pad_len)


def gen_random_uint32() -> int:
    return struct.unpack(">I", randbytes(4))[0]


__all__ = [
    "ArgonID",
    "Argon2Params",
    "CipherKey",
    "EncryptedBytes",
    "IV",
    "MemoryCost",
    "Nonce",
    "Parallelism",
    "Rounds",
]
