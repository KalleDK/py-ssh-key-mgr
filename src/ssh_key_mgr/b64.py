import base64
from typing import overload

from ssh_key_mgr.utils import wrap_lines


def to_line(data: bytes) -> bytes:
    return base64.b64encode(data)


def to_lines(data: bytes, width: int = 64) -> list[bytes]:
    line = to_line(data)
    return wrap_lines(line, width=width)


def from_line(line: bytes) -> bytes:
    return base64.b64decode(line.strip())


def from_lines(lines: list[bytes]) -> bytes:
    data = b"".join(line.strip() for line in lines)
    return from_line(data)


@overload
def encode(data: bytes) -> bytes: ...


@overload
def encode(data: bytes, width: None = ...) -> bytes: ...


@overload
def encode(data: bytes, width: int) -> list[bytes]: ...


def encode(data: bytes, width: int | None = None) -> bytes | list[bytes]:
    data = base64.standard_b64encode(data)
    if width is None:
        return data
    return wrap_lines(data, width=width)


def decode(data: bytes | list[bytes]) -> bytes:
    if isinstance(data, list):
        data = b"".join(line.strip() for line in data)
    return base64.standard_b64decode(data.strip() + b"====")
