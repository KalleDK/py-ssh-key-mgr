import dataclasses
import enum


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _bytes:
    value: bytes

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _int:
    value: int

    def __int__(self) -> int:
        return self.value


class Salt(_bytes):
    pass


class TimeCost(_int):
    pass


class MemoryCost(_int):
    pass


class Parallelism(_int):
    pass


class ArgonID(enum.StrEnum):
    D = "Argon2d"
    I = "Argon2i"  # noqa: E741
    ID = "Argon2id"


DEFAULT_SALT_LENGTH = 16
DEFAULT_ID = ArgonID.ID
DEFAULT_MEMORY = MemoryCost(8192)
DEFAULT_PASSES = TimeCost(21)
DEFAULT_PARALLELISM = Parallelism(1)


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Argon2Params:
    type: ArgonID
    memory_cost: MemoryCost
    time_cost: TimeCost
    parallelism: Parallelism
    salt: Salt
    hash_length: int


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Argon2ParamsTmpl:
    type: ArgonID
    argon2_memory_cost: MemoryCost
    argon2_time_cost: TimeCost
    argon2_parallelism: Parallelism
    salt_length: int
