import random
from types import FunctionType, MethodType
from unittest.mock import patch

import pytest

import ssh_key_mgr.encryption


def fake_randbytes(n: int) -> bytes:
    return bytes(range(1, n + 1))


def name(o: FunctionType | MethodType) -> str:
    return o.__module__ + "." + o.__name__


@pytest.fixture()
def no_randbytes():
    with patch(name(ssh_key_mgr.encryption.randbytes), wraps=fake_randbytes):
        yield


@pytest.fixture()
def no_random_randbytes():
    with patch(name(random.randbytes), wraps=fake_randbytes):
        yield
