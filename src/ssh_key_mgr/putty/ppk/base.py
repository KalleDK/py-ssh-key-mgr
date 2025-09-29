import enum
from typing import TypeGuard


class hexbytes:
    pass


class Notset(enum.Enum):
    Notset = enum.auto()


NOTSET = Notset.Notset

R_TYPES = (hexbytes,)
P_TYPES = (int, str, bytes)
UNDERLAYING_TYPES = (*R_TYPES, *P_TYPES)

R_TYPES_T = hexbytes
P_TYPES_T = int | str | bytes
UNDERLAYING_TYPES_T = R_TYPES_T | P_TYPES_T


def is_p_types_t(annotation: type | None) -> TypeGuard[type[P_TYPES_T]]:
    return annotation in P_TYPES


def is_r_types_t(annotation: type | None) -> TypeGuard[type[R_TYPES_T]]:
    return annotation in R_TYPES
