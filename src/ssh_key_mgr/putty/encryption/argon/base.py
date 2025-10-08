import dataclasses
import enum
from typing import NewType

Salt = NewType("Salt", bytes)
MemoryCost = NewType("MemoryCost", int)
TimeCost = NewType("TimeCost", int)
Parallelism = NewType("Parallelism", int)


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
