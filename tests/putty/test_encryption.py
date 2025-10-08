import pytest

from ssh_key_mgr.putty.checksum import MacKey
from ssh_key_mgr.secretstr import SecretBytes

try:
    import argon2  # type: ignore
except ImportError:  # pragma: no cover
    argon2 = None  # type: ignore
import ssh_key_mgr.putty.encryption as enc
from ssh_key_mgr.putty.encryption import IV, CipherKey, argon
from ssh_key_mgr.putty.encryption.argon.base import MemoryCost, Parallelism, TimeCost
from tests.putty.data import (
    ENC_AES256_CBC,
    INVALID_PASSPHRASE,
    KEY_NAMES,
    KEY_NAMES_T,
    PASSPHRASES,
    PUTTY_DECRYPTED,
    PUTTY_DECRYPTION_PARAMS,
    PUTTY_ENC_NAMES,
    PUTTY_ENC_NAMES_T,
    PUTTY_ENCRYPTED,
    PUTTY_ENCRYPTION_PARAMS,
    PUTTY_MAC_KEY,
)


@pytest.mark.skipif(argon2 is None, reason="argon2-cffi is not installed")
def test_derive_key():
    want_cipher = CipherKey(b"#!\xb0\xfeTy\x1az\xc2W,O/\xcb\xe6\xe7_\xfcxX%q\xd9[7\x0f\xd3\xa2p\xf6\xeea")
    want_iv = IV(b"\x9b\xe6\xf5w\xfa\xc3\x8a\xc30wg\xa3 \xe4\xe0D")
    want_mac_key = MacKey(b"y\xfc\x0f5Ea14\xd0\x02\x90u\x11*\x0cah[\xccC#\x916\x83)\xa3\t\xdcK{\xec\x0b")

    passphrase = SecretBytes(b"correct horse battery staple")

    argon_params = enc.Argon2Params(
        type=argon.ArgonID.ID,
        memory_cost=MemoryCost(8192),
        time_cost=TimeCost(21),
        parallelism=Parallelism(1),
        salt=argon.Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
    )
    aes_params = enc.AESParams(
        block_size=16,
        cipher_iv_length=16,
        cipher_key_length=32,
        mac_key_length=32,
    )

    got_cipher, got_iv, got_mac_key = enc.derive_aes_key(argon_params, aes_params, passphrase)
    assert got_cipher.get_secret_value() == want_cipher.get_secret_value(), "Cipher key mismatch"
    assert got_iv.get_secret_value() == want_iv.get_secret_value(), "IV mismatch"
    assert got_mac_key.get_secret_value() == want_mac_key.get_secret_value(), "MAC key mismatch"


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_aes_encrypt(no_randomness: None, enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")

    params = PUTTY_ENCRYPTION_PARAMS[enc_name][key_name]
    decrypted = PUTTY_DECRYPTED[enc_name][key_name]
    passphrase = PASSPHRASES[key_name][enc_name]

    want_encrypted = PUTTY_ENCRYPTED[enc_name][key_name]
    want_params = PUTTY_DECRYPTION_PARAMS[enc_name][key_name]
    want_mac_key = PUTTY_MAC_KEY[enc_name][key_name]

    got_params = params.generate_params()

    got_encrypted, got_mac_key = got_params.encrypt(decrypted, passphrase)

    assert got_encrypted == want_encrypted, "Encrypted data mismatch"
    assert got_params == want_params, "Params mismatch"
    assert got_mac_key.get_secret_value() == want_mac_key.get_secret_value(), "MAC key mismatch"


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decrypt(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")

    params = PUTTY_DECRYPTION_PARAMS[enc_name][key_name]
    encrypted = PUTTY_ENCRYPTED[enc_name][key_name]
    passphrase = PASSPHRASES[key_name][enc_name]

    want_decrypted = PUTTY_DECRYPTED[enc_name][key_name]
    want_mac_key = PUTTY_MAC_KEY[enc_name][key_name]

    got_decrypted, got_mac_key = params.decrypt(encrypted, passphrase)

    assert got_decrypted == want_decrypted, "Decrypted data mismatch"
    assert got_mac_key.get_secret_value() == want_mac_key.get_secret_value(), "MAC key mismatch"


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_decrypt_invalid_passphrase(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")

    params = PUTTY_DECRYPTION_PARAMS[enc_name][key_name]
    encrypted = PUTTY_ENCRYPTED[enc_name][key_name]
    passphrase = INVALID_PASSPHRASE[enc_name]

    with pytest.raises(ValueError):
        params.decrypt(encrypted, passphrase)


@pytest.mark.parametrize("enc_name", PUTTY_ENC_NAMES)
@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_encrypt_invalid_passphrase(enc_name: PUTTY_ENC_NAMES_T, key_name: KEY_NAMES_T):
    if argon2 is None and enc_name == ENC_AES256_CBC:
        pytest.skip(reason="argon2-cffi is not installed")

    params = PUTTY_ENCRYPTION_PARAMS[enc_name][key_name]
    decrypted = PUTTY_DECRYPTED[enc_name][key_name]
    passphrase = INVALID_PASSPHRASE[enc_name]

    with pytest.raises(ValueError):
        params.generate_params().encrypt(decrypted, passphrase)


def test_aes_padding(no_randomness: None):
    assert enc.add_padding(b"abc", 16) == b"abc" + b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r"
