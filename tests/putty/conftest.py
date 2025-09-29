from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

import ssh_key_mgr.putty.encryption


def name(o: Callable[..., Any]) -> str:
    return o.__module__ + "." + o.__name__


def fake_gen_salt(size: int) -> ssh_key_mgr.putty.encryption.Salt:
    return ssh_key_mgr.putty.encryption.Salt(bytes(range(1, size + 1)))


def fake_gen_padding(size: int, block_size: int = 16) -> bytes:
    pad_len = (block_size - (size % block_size)) % block_size
    return bytes(range(1, pad_len + 1))


def fake_randbytes(size: int) -> bytes:
    return bytes(range(1, size + 1))


@pytest.fixture
def no_randomness():
    with (
        patch(
            "ssh_key_mgr.putty.encryption.gen_salt",
            wraps=fake_gen_salt,
        ),
        patch(
            name(ssh_key_mgr.putty.encryption.aes.gen_padding),
            wraps=fake_gen_padding,
        ),
    ):
        yield


@pytest.fixture
def no_randbytes():
    with patch("random.randbytes", wraps=fake_randbytes):
        yield
