import dataclasses

import pytest

try:
    import argon2  # type: ignore
except ImportError:  # pragma: no cover
    argon2 = None  # type: ignore
from ssh_key_mgr.putty import PuttyFile, PuttyFileV3, PuttyKey, PuttyPrivateKeyRSA, ppk
from ssh_key_mgr.putty.encryption.argon.base import Salt

from .data import (
    ENC_AES256_CBC,
    INVALID_PASSPHRASE,
    KEY_NAMES,
    KEY_NAMES_T,
    PASSPHRASES,
    PUTTY_ENC_NAMES,
    PUTTY_ENC_NAMES_T,
    PUTTY_ENCRYPTION_PARAMS,
    PUTTY_FILE_V3,
    PUTTY_KEY,
    PUTTY_PPK_V3,
    PUTTY_PUBLIC_KEYS,
)


def fake_gen_salt(size: int) -> Salt:
    return Salt(bytes(range(1, size + 1)))


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_encrypt(no_randomness: None, enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")
    want = PUTTY_FILE_V3[enc_name][key_name]
    key = PUTTY_KEY[key_name]
    params = PUTTY_ENCRYPTION_PARAMS[enc_name][key_name]
    passphrase = PASSPHRASES[key_name][enc_name]
    got = PuttyFileV3.encrypt(key, params, passphrase)
    assert got == want


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decrypt(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")
    file = PUTTY_FILE_V3[enc_name][key_name]
    want = PUTTY_KEY[key_name]
    passphrase = PASSPHRASES[key_name][enc_name]
    got = file.decrypt(passphrase)
    assert got == want


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decrypt_fails_with_invalid_passphrase(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    passphrase = INVALID_PASSPHRASE[enc_name]
    file = PUTTY_FILE_V3[enc_name][key_name]
    with pytest.raises(ValueError):
        file.decrypt(passphrase)


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_encrypt_fails_with_invalid_passphrase(no_randomness: None, enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    passphrase = INVALID_PASSPHRASE[enc_name]
    key = PUTTY_KEY[key_name]
    params = PUTTY_ENCRYPTION_PARAMS[enc_name][key_name]
    with pytest.raises(ValueError):
        PuttyFileV3.encrypt(key, params, passphrase)


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_encode(no_randomness: None, enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    want = PUTTY_PPK_V3[enc_name][key_name]
    file = PUTTY_FILE_V3[enc_name][key_name]
    got = ppk.marshal(file)
    assert got == want


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decode_specific(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    want = PUTTY_FILE_V3[enc_name][key_name]
    ppk_data = PUTTY_PPK_V3[enc_name][key_name]
    got = ppk.unmarshal(want.__class__, ppk_data)
    assert got == want


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decode(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    want = PUTTY_FILE_V3[enc_name][key_name]
    ppk_data = PUTTY_PPK_V3[enc_name][key_name]
    got = ppk.unmarshal(PuttyFile, ppk_data)
    assert got == want


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_get_public_key_unverified(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    file = PUTTY_FILE_V3[enc_name][key_name]
    want = PUTTY_PUBLIC_KEYS[key_name]
    got = file.get_public_key_unverified()
    assert got == want


def test_invalid_key_class():
    with pytest.raises(TypeError, match="private must be a subclass of PuttyPrivateKey"):

        @dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
        class InvalidKey1(PuttyKey):  # pyright: ignore[reportUnusedClass]
            key_type = "ssh-rsa-1"
            private: int  # type: ignore
            public: int  # type: ignore

    with pytest.raises(TypeError, match="public must be a subclass of PuttyPublicKey"):

        @dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
        class InvalidKey2(PuttyKey):  # pyright: ignore[reportUnusedClass]
            key_type = "ssh-rsa-2"
            private: PuttyPrivateKeyRSA
            public: int  # type: ignore
