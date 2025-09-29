import importlib.util

# import itertools
import itertools
from typing import Callable

import pytest

from ssh_key_mgr.putty.encryption.enc_aes256_cbc_argon2 import Encryption_AES256_CBC
from tests.putty.data import (
    #    ENC_AES256_CBC,
    #    KEY_NAMES,
    #    KEY_NAMES_T,
    PUTTY_AES,
    PUTTY_ARGON,
    PUTTY_ENC_NAMES,
    PUTTY_KEY_NAMES,
    #    PUTTY_ENC_NAMES,
    #    PUTTY_ENC_NAMES_T,
)

argon_present = importlib.util.find_spec("argon2") is not None
cryptodome_present = importlib.util.find_spec("Crypto") is not None
argon_missing = not argon_present
cryptodome_missing = not cryptodome_present
crypto_present = argon_present or cryptodome_present
crypto_missing = argon_missing or cryptodome_missing


def _crypto_missing_reason() -> str:
    libs: list[str] = []
    if not cryptodome_present:
        libs.append("PyCryptodome")
    if not argon_present:
        libs.append("argon2-cffi")
    return " and ".join(libs) + " is not installed"


crypto_missing_reason = _crypto_missing_reason()


def _crypto_present_reason() -> str:
    libs: list[str] = []
    if cryptodome_present:
        libs.append("PyCryptodome")
    if argon_present:
        libs.append("argon2-cffi")
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


def mark_skip_if_cryptodome_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not cryptodome_present, reason="PyCryptodome is not installed")(fn)


def mark_skip_if_cryptodome_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(cryptodome_present, reason="PyCryptodome is installed")(fn)


def mark_skip_if_crypto_missing[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(not crypto_present, reason=crypto_missing_reason)(fn)


def mark_skip_if_crypto_present[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    return pytest.mark.skipif(crypto_present, reason=crypto_present_reason)(fn)


# @pytest.fixture(params=KEY_NAMES)
# def key_names(request: pytest.FixtureRequest):
#    return request.param


@pytest.fixture(params=PUTTY_ARGON.keys())
def argon_name(request: pytest.FixtureRequest):
    return request.param


@pytest.fixture(params=PUTTY_AES.keys())
def aes_name(request: pytest.FixtureRequest):
    return request.param


@pytest.fixture(params=itertools.product(PUTTY_KEY_NAMES, PUTTY_ENC_NAMES), ids=lambda x: f"{x[0]}-{x[1]}")
def key_enc_name(request: pytest.FixtureRequest) -> tuple[str, str]:
    key_name, enc_name = request.param
    if enc_name == Encryption_AES256_CBC.encryption_type.upper().replace("-", "_"):
        skip_if_crypto_missing()
    return key_name, enc_name
