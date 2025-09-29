import pytest

try:
    from Crypto.Cipher import AES  # type: ignore
except ImportError:  # pragma: no cover
    AES = None  # type: ignore

from ssh_key_mgr.putty.encryption import aes
from tests.putty.data import PUTTY_AES


@pytest.mark.skipif(AES is None, reason="PyCryptodome is not installed")
@pytest.mark.parametrize("argon_name", PUTTY_AES.keys())
def test_decrypt(argon_name: str):
    want = PUTTY_AES[argon_name]["Decrypted"]
    encrypted = PUTTY_AES[argon_name]["Encrypted"]
    cipher = PUTTY_AES[argon_name]["CipherKey"]
    iv = PUTTY_AES[argon_name]["IV"]
    got = aes.decrypt(encrypted, cipher, iv)

    assert got == want


@pytest.mark.skipif(AES is not None, reason="PyCryptodome is installed")
@pytest.mark.parametrize("argon_name", PUTTY_AES.keys())
def test_decrypt_fails_import(argon_name: str):
    with pytest.raises(ImportError, match="PyCryptodome is required for AES decryption/encryption"):
        want = PUTTY_AES[argon_name]["Decrypted"]
        encrypted = PUTTY_AES[argon_name]["Encrypted"]
        cipher = PUTTY_AES[argon_name]["CipherKey"]
        iv = PUTTY_AES[argon_name]["IV"]
        got = aes.decrypt(encrypted, cipher, iv)

        assert got == want


@pytest.mark.skipif(AES is None, reason="PyCryptodome is not installed")
@pytest.mark.parametrize("argon_name", PUTTY_AES.keys())
def test_encrypt(argon_name: str):
    want = PUTTY_AES[argon_name]["Encrypted"]
    decrypted = PUTTY_AES[argon_name]["Decrypted"]
    cipher = PUTTY_AES[argon_name]["CipherKey"]
    iv = PUTTY_AES[argon_name]["IV"]
    got = aes.encrypt(decrypted, cipher, iv)

    assert got == want


@pytest.mark.skipif(AES is not None, reason="PyCryptodome is installed")
@pytest.mark.parametrize("argon_name", PUTTY_AES.keys())
def test_encrypt_fails_import(argon_name: str):
    with pytest.raises(ImportError, match="PyCryptodome is required for AES decryption/encryption"):
        want = PUTTY_AES[argon_name]["Encrypted"]
        decrypted = PUTTY_AES[argon_name]["Decrypted"]
        cipher = PUTTY_AES[argon_name]["CipherKey"]
        iv = PUTTY_AES[argon_name]["IV"]
        got = aes.encrypt(decrypted, cipher, iv)

        assert got == want


def test_cipher_key():
    assert aes.CipherKey(b"\x00" * 16).get_secret_value() == aes.CipherKey.fromhex("00" * 16).get_secret_value()
    assert aes.CipherKey(b"\x00" * 16).get_secret_value() != aes.CipherKey(b"\x01" * 16).get_secret_value()


def test_iv():
    assert aes.IV(b"\x00" * 16).get_secret_value() == aes.IV.fromhex("00" * 16).get_secret_value()
    assert aes.IV(b"\x00" * 16).get_secret_value() != aes.IV(b"\x01" * 16).get_secret_value()


def test_encrypted_bytes():
    a = aes.EncryptedBytes(b"abc")
    b = aes.EncryptedBytes(b"abc")
    c = aes.EncryptedBytes(b"def")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)
    assert hash(a) != hash(c)
    assert bytes(a) == a.value
    assert a.fromhex("616263") == a
    assert len(a) == 3


def test_gen_padding(no_randbytes: None):
    assert aes.gen_padding(0) == b""
    assert aes.gen_padding(1) == b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    assert aes.gen_padding(15) == b"\x01"
    assert aes.gen_padding(16) == b""
    assert aes.gen_padding(17) == b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    assert aes.gen_padding(31) == b"\x01"
    assert aes.gen_padding(32) == b""
