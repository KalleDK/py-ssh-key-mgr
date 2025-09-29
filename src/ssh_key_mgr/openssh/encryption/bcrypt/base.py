import dataclasses


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _bytes:
    value: bytes

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _uint32:
    value: int

    def __int__(self) -> int:
        return self.value


class Salt(_bytes):
    pass


class Rounds(_uint32):
    pass


MAX_SALT_SIZE = 22
