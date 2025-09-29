import dataclasses

import pytest

from ssh_key_mgr.encryption import SecretBytes
from ssh_key_mgr.putty import PuttyFile, PuttyFileV3, PuttyKeyPair, PuttyPrivateKeyRSA, ppk
from tests.putty.data import PUTTY_KEY_TESTS, PUTTY_PUBLIC_KEYS


def test_encrypt(no_randbytes: None, key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    key = PUTTY_KEY_TESTS[key_name]["Obj"]
    params = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["Params"]
    passphrase = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["Passphrase"]
    got = PuttyFileV3.encrypt(key, params, passphrase)
    assert got == want


def test_decrypt(key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_KEY_TESTS[key_name]["Obj"]
    file = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    passphrase = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["Passphrase"]
    got = file.decrypt(passphrase)
    assert got == want


def test_decrypt_fails_with_invalid_passphrase(key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name

    file = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    with pytest.raises(ValueError):
        file.decrypt(SecretBytes(b"invalid-passphrase"))


def test_encrypt_fails_with_invalid_passphrase(no_randbytes: None, key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    key = PUTTY_KEY_TESTS[key_name]["Obj"]
    params = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["Params"]
    passphrase = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["Passphrase"]
    if passphrase is None:
        passphrase = SecretBytes(b"invalid-passphrase")
    else:
        passphrase = None
    with pytest.raises(ValueError):
        PuttyFileV3.encrypt(key, params, passphrase)


def test_encode(no_randbytes: None, key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["File"].encode()
    file = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    got = ppk.marshal(file)
    assert got == want


def test_decode_specific(key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    ppk_data = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["File"]
    got = ppk.unmarshal(want.__class__, ppk_data.encode())
    assert got == want


def test_decode(key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    ppk_data = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["File"]
    got = ppk.unmarshal(PuttyFile, ppk_data.encode())
    assert got == want


def test_get_public_key_unverified(key_enc_name: tuple[str, str]):
    key_name, enc_name = key_enc_name
    want = PUTTY_PUBLIC_KEYS[key_name]
    file = PUTTY_KEY_TESTS[key_name]["Encryptions"][enc_name]["FileObj"]
    got = file.get_public_key_unverified()
    assert got == want


def test_invalid_key_class():
    with pytest.raises(TypeError, match="private must be a subclass of PuttyPrivateKey"):

        @dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
        class InvalidKey1(PuttyKeyPair):  # pyright: ignore[reportUnusedClass]
            key_type = "ssh-rsa-1"
            private: int  # type: ignore
            public: int  # type: ignore

    with pytest.raises(TypeError, match="public must be a subclass of PuttyPublicKey"):

        @dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
        class InvalidKey2(PuttyKeyPair):  # pyright: ignore[reportUnusedClass]
            key_type = "ssh-rsa-2"
            private: PuttyPrivateKeyRSA
            public: int  # type: ignore
