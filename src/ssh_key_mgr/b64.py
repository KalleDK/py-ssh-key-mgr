import base64

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
