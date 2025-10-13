import importlib
import importlib.util
import random
from collections.abc import Callable
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


argon_present = importlib.util.find_spec("argon2") is not None
cryptodome_present = importlib.util.find_spec("Crypto") is not None
bcrypt_present = importlib.util.find_spec("bcrypt") is not None
argon_missing = not argon_present
cryptodome_missing = not cryptodome_present
bcrypt_missing = not bcrypt_present
crypto_present = argon_present or cryptodome_present or bcrypt_present
crypto_missing = argon_missing or cryptodome_missing or bcrypt_missing


def _crypto_missing_reason() -> str:
    libs: list[str] = []
    if not cryptodome_present:
        libs.append("PyCryptodome")
    if not argon_present:
        libs.append("argon2-cffi")
    if not bcrypt_present:
        libs.append("bcrypt")
    return " and ".join(libs) + " is not installed"


crypto_missing_reason = _crypto_missing_reason()


def _crypto_present_reason() -> str:
    libs: list[str] = []
    if cryptodome_present:
        libs.append("PyCryptodome")
    if argon_present:
        libs.append("argon2-cffi")
    if bcrypt_present:
        libs.append("bcrypt")
    return " and ".join(libs) + " is installed"


crypto_present_reason = _crypto_present_reason()


def skip_if_crypto_missing():
    if crypto_missing:
        pytest.skip(reason=crypto_missing_reason)


def skip_if_crypto_present():
    if crypto_present:
        pytest.skip(reason=_crypto_present_reason())


def mark_skip_if_argon_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not argon_present, reason="argon2-cffi is not installed")(fn)


def mark_skip_if_argon_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(argon_present, reason="argon2-cffi is installed")(fn)


def mark_skip_if_bcrypt_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not bcrypt_present, reason="bcrypt is not installed")(fn)


def mark_skip_if_bcrypt_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(bcrypt_present, reason="bcrypt is installed")(fn)


def mark_skip_if_cryptodome_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not cryptodome_present, reason="PyCryptodome is not installed")(fn)


def mark_skip_if_cryptodome_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(cryptodome_present, reason="PyCryptodome is installed")(fn)


def mark_skip_if_crypto_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not crypto_present, reason=crypto_missing_reason)(fn)


def mark_skip_if_crypto_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(crypto_present, reason=crypto_present_reason)(fn)
