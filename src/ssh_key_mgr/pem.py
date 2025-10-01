import base64
import re
from collections.abc import Iterable
from typing import NamedTuple

HEADER_RE_STR = rb"----[- ]BEGIN (?P<header>[A-Z][A-Z ]*[A-Z]|[A-Z])[- ]----"
HEADER_RE = re.compile(HEADER_RE_STR)

FOOTER_RE_STR = rb"----[- ]END (?P<footer>[A-Z][A-Z ]*[A-Z]|[A-Z])[- ]----"
FOOTER_RE = re.compile(FOOTER_RE_STR)

DATA_RE_STR = rb"(?P<data>[A-Za-z0-9+/=\s]+)"
DATA_RE = re.compile(DATA_RE_STR)

PEM_RE = re.compile(HEADER_RE_STR + rb"\r?\n" + DATA_RE_STR + rb"\r?\n" + FOOTER_RE_STR)


def is_pem(data: bytes) -> bool:
    return bool(PEM_RE.search(data))


class PEMBlock(NamedTuple):
    header: str
    footer: str
    data: bytes


def iter(data: bytes) -> Iterable[PEMBlock]:
    for match in PEM_RE.finditer(data):
        header = match.group("header").decode("utf-8")
        footer = match.group("footer").decode("utf-8")
        b64data = match.group("data").replace(b"\n", b"").replace(b"\r", b"").replace(b" ", b"")
        if header != footer:
            raise ValueError(f"Header and footer do not match: {header} != {footer}")
        decoded_data = base64.b64decode(b64data)
        yield PEMBlock(header=header, footer=footer, data=decoded_data)


def unmarshal(data: bytes) -> list[PEMBlock]:
    return list(iter(data))


def to_base64_lines(data: bytes, width: int = 64) -> list[bytes]:
    raw = base64.b64encode(data)
    lines = [raw[i : i + width] for i in range(0, len(raw), width)]
    return lines


def marshal(block: PEMBlock, *blocks: PEMBlock, width: int = 64, use_spaces: bool = True) -> bytes:
    blocks = (block,) + blocks
    lines: list[bytes] = []
    space = " " if use_spaces else "-"
    for block in blocks:
        lines.append(f"----{space}BEGIN {block.header}{space}----".encode("utf-8"))
        lines.extend(to_base64_lines(block.data, width=width))
        lines.append(f"----{space}END {block.footer}{space}----".encode("utf-8"))
        lines.append(b"")
    return b"\n".join(lines)
