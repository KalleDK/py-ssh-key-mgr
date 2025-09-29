from io import BytesIO
from typing import ClassVar

import pytest

from ssh_key_mgr.putty import PuttyFormatVersion, ppk
from ssh_key_mgr.putty.ppk.base import is_p_types_t
from ssh_key_mgr.putty.ppk.stream import BytesField, Field, HexField, IntField, StrField

SMALL_PPK_FILE = b"""PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: rsa-key-20250925
"""


class SmallPPK(ppk.File):
    file_version: ClassVar[PuttyFormatVersion] = PuttyFormatVersion.V3
    key_type: ClassVar[str] = "ssh-rsa"
    encryption: str
    comment: str


def test_file_unmarshal():
    want = SmallPPK(
        encryption="aes256-cbc",
        comment="rsa-key-20250925",
    )
    got = ppk.unmarshal(SmallPPK, SMALL_PPK_FILE)
    assert got == want


def test_file_marshal():
    want = SMALL_PPK_FILE
    got = ppk.marshal(
        SmallPPK(
            encryption="aes256-cbc",
            comment="rsa-key-20250925",
        )
    )
    assert got == want


def test_empty_file():
    stream = ppk.StreamReader(BytesIO(b""))
    assert stream.eof()


SMALL_PPK_FILE_SPACE = b"""PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc

Comment: rsa-key-20250925
"""


def test_file_space_unmarshal():
    want = SmallPPK(
        encryption="aes256-cbc",
        comment="rsa-key-20250925",
    )
    got = ppk.unmarshal(SmallPPK, SMALL_PPK_FILE_SPACE)
    assert got == want


def test_empty_file_read():
    stream = ppk.StreamReader(BytesIO(b""))
    with pytest.raises(EOFError, match="No more fields to read"):
        stream.read_bytes()


SMALL_PPK_FILE_TYPES = b"""PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: rsa-key-20250925
Bytes: AQIDBAUGBwg=
Integer: 12345678901234567890
HexInteger: 0102030405060708090a0b0c0d0e0f
"""


def test_file_types_unmarshal():
    stream = ppk.StreamReader(BytesIO(SMALL_PPK_FILE_TYPES))

    want = StrField("File-Version", "PuTTY-User-Key-File-3")
    got = stream.read(StrField)
    assert got == want

    want = StrField("Key-Type", "ssh-rsa")
    got = stream.read(StrField)
    assert got == want

    want = StrField("Encryption", "aes256-cbc")
    got = stream.read(StrField)
    assert got == want

    want = StrField("Comment", "rsa-key-20250925")
    got = stream.read(StrField)
    assert got == want

    want = stream.read(BytesField)
    got = BytesField("Bytes", b"\x01\x02\x03\x04\x05\x06\x07\x08")
    assert got == want

    want = stream.read(IntField)
    got = IntField("Integer", 12345678901234567890)
    assert got == want

    want = stream.read(HexField)
    got = HexField("HexInteger", b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    assert got == want


def test_file_types_unmarshal_invalid():
    stream = ppk.StreamReader(BytesIO(SMALL_PPK_FILE_TYPES))

    with pytest.raises(TypeError, match=r"Unsupported type: ssh_key_mgr.putty.ppk.stream.Field\[int\]"):
        stream.read(Field[int])  # type: ignore


def test_file_types_unmarshal_named_wrong():
    stream = ppk.StreamReader(BytesIO(SMALL_PPK_FILE_TYPES))

    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_str("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_str("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_str("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_str("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_bytes("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_int("Wrong-Name")
    with pytest.raises(ValueError, match="Expected field name "):
        stream.read_named_hexbytes("Wrong-Name")


def test_is_p_type():
    assert is_p_types_t(int)
