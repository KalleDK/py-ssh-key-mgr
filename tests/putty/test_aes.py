import inspect

import pytest

from ssh_key_mgr.putty.encryption import aes
from tests.conftest import mark_skip_if_crypto_present, mark_skip_if_cryptodome_missing
from tests.putty.data import PUTTY_AES


@mark_skip_if_cryptodome_missing
def test_signature_decrypt():
    from ssh_key_mgr.putty.encryption.aes import impl, stub

    got = inspect.signature(impl.decrypt)

    want = inspect.signature(stub.decrypt)
    assert got.return_annotation == want.return_annotation
    assert got.parameters == want.parameters


@mark_skip_if_cryptodome_missing
def test_signature_encrypt():
    from ssh_key_mgr.putty.encryption.aes import impl, stub

    got = inspect.signature(impl.encrypt)

    want = inspect.signature(stub.encrypt)
    assert got.return_annotation == want.return_annotation
    assert got.parameters == want.parameters


@mark_skip_if_cryptodome_missing
def test_decrypt(aes_name: str):
    want = PUTTY_AES[aes_name]["Decrypted"]
    encrypted = PUTTY_AES[aes_name]["Encrypted"]
    cipher = PUTTY_AES[aes_name]["CipherKey"]
    iv = PUTTY_AES[aes_name]["IV"]
    got = aes.decrypt(encrypted, cipher, iv)

    assert got == want


@mark_skip_if_crypto_present
def test_decrypt_fails_import(aes_name: str):
    with pytest.raises(ImportError, match="PyCryptodome is required for AES decryption/encryption"):
        want = PUTTY_AES[aes_name]["Decrypted"]
        encrypted = PUTTY_AES[aes_name]["Encrypted"]
        cipher = PUTTY_AES[aes_name]["CipherKey"]
        iv = PUTTY_AES[aes_name]["IV"]
        got = aes.decrypt(encrypted, cipher, iv)

        assert got == want


@mark_skip_if_cryptodome_missing
def test_encrypt(aes_name: str):
    want = PUTTY_AES[aes_name]["Encrypted"]
    decrypted = PUTTY_AES[aes_name]["Decrypted"]
    cipher = PUTTY_AES[aes_name]["CipherKey"]
    iv = PUTTY_AES[aes_name]["IV"]
    got = aes.encrypt(decrypted, cipher, iv)

    assert got == want


@mark_skip_if_crypto_present
def test_encrypt_fails_import(aes_name: str):
    with pytest.raises(ImportError, match="PyCryptodome is required for AES decryption/encryption"):
        want = PUTTY_AES[aes_name]["Encrypted"]
        decrypted = PUTTY_AES[aes_name]["Decrypted"]
        cipher = PUTTY_AES[aes_name]["CipherKey"]
        iv = PUTTY_AES[aes_name]["IV"]
        got = aes.encrypt(decrypted, cipher, iv)

        assert got == want
