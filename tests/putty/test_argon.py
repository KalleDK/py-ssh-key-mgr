import importlib.util

import pytest

from ssh_key_mgr.putty.encryption import argon
from tests.putty.data import PUTTY_ARGON

has_argon = importlib.util.find_spec("argon2") is not None


def skip_if_argon_missing():
    return pytest.mark.skipif(not has_argon, reason="argon2-cffi is not installed")


def skip_if_argon_present():
    return pytest.mark.skipif(has_argon, reason="argon2-cffi is installed")


@skip_if_argon_missing()
@pytest.mark.parametrize("test_name", PUTTY_ARGON.keys())
def test_hash(test_name: str):
    want = PUTTY_ARGON[test_name]["Hash"]
    params = PUTTY_ARGON[test_name]["Params"]
    passphrase = PUTTY_ARGON[test_name]["Passphrase"]

    got = argon.hash_passphrase(params, len(want), passphrase)
    assert got == want


@skip_if_argon_present()
@pytest.mark.parametrize("test_name", PUTTY_ARGON.keys())
def test_hash_import_error(test_name: str):
    with pytest.raises(ImportError, match="argon2-cffi is required for Argon2 hashing"):
        want = PUTTY_ARGON[test_name]["Hash"]
        params = PUTTY_ARGON[test_name]["Params"]
        passphrase = PUTTY_ARGON[test_name]["Passphrase"]

        got = argon.hash_passphrase(params, len(want), passphrase)
        assert got == want


def test_salt():
    assert argon.Salt(b"\x00" * 16) == argon.Salt(b"\x00" * 16)
    assert argon.Salt(b"\x00" * 16) != argon.Salt(b"\x01" * 16)
    assert bytes(argon.Salt(b"\x00" * 16)) == b"\x00" * 16
    assert len(argon.Salt(b"\x00" * 16)) == 16


@skip_if_argon_missing()
def test_gen_salt(no_randbytes: None):
    assert argon.gen_salt(16) == argon.Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10")


@skip_if_argon_present()
def test_gen_salt_import_error(no_randbytes: None):
    with pytest.raises(ImportError, match="argon2-cffi is required for Argon2 salt generation"):
        argon.gen_salt(16)


def test_argon_type():
    pytest.importorskip("argon2")
    import argon2

    from ssh_key_mgr.putty.encryption.argon.impl import argon_type

    test_cases_argon_type = [
        (argon.ArgonID.ID, argon2.Type.ID),
        (argon.ArgonID.I, argon2.Type.I),
        (argon.ArgonID.D, argon2.Type.D),
    ]

    for input_type, want in test_cases_argon_type:
        got = argon_type(input_type)
        assert got == want
