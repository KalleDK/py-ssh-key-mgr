import pytest

from ssh_key_mgr.encryption import ArgonID
from ssh_key_mgr.putty.encryption import argon
from tests.putty.conftest import mark_skip_if_argon_missing, mark_skip_if_argon_present
from tests.putty.data import PUTTY_ARGON


@mark_skip_if_argon_missing
def test_hash(argon_name: str):
    want = PUTTY_ARGON[argon_name]["Hash"]
    params = PUTTY_ARGON[argon_name]["Params"]
    passphrase = PUTTY_ARGON[argon_name]["Passphrase"]
    hash_len = PUTTY_ARGON[argon_name]["HashLength"]

    got = argon.hash_passphrase(params, hash_len, passphrase)
    assert got == want


@mark_skip_if_argon_present
def test_hash_import_error(argon_name: str):
    with pytest.raises(ImportError, match="argon2-cffi is required for Argon2 hashing"):
        want = PUTTY_ARGON[argon_name]["Hash"]
        params = PUTTY_ARGON[argon_name]["Params"]
        passphrase = PUTTY_ARGON[argon_name]["Passphrase"]
        hash_len = PUTTY_ARGON[argon_name]["HashLength"]

        got = argon.hash_passphrase(params, hash_len, passphrase)
        assert got == want


@mark_skip_if_argon_missing
def test_argon_type():
    import argon2

    from ssh_key_mgr.putty.encryption.argon.impl import argon_type

    test_cases_argon_type = [
        (ArgonID.ID, argon2.Type.ID),
        (ArgonID.I, argon2.Type.I),
        (ArgonID.D, argon2.Type.D),
    ]

    for input_type, want in test_cases_argon_type:
        got = argon_type(input_type)
        assert got == want
