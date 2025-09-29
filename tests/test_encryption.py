from ssh_key_mgr.encryption import IV, CipherKey, EncryptedBytes, Salt, SecretBytes, SecretStr, randbytes


def test_eq():
    a = SecretBytes(b"abc")
    b = SecretBytes(b"abc")
    c = SecretBytes(b"def")
    assert a == b
    assert a != c


def test_hash():
    a = SecretBytes(b"abc")
    b = SecretBytes(b"abc")
    c = SecretBytes(b"def")
    assert hash(a) == hash(b)
    assert hash(a) != hash(c)


def test_get_secret_value():
    a = SecretBytes(b"abc")
    assert a.get_secret_value() == b"abc"

    b = SecretStr("abc")
    assert b.get_secret_value() == "abc"


def test_repr():
    a = SecretBytes(b"abc")
    assert repr(a) == "SecretBytes(\"b'**********'\")"

    b = SecretStr("abc")
    assert repr(b) == "SecretStr('**********')"


def test_str():
    a = SecretBytes(b"abc")
    assert str(a) == "b'**********'"

    a_empty = SecretBytes(b"")
    assert str(a_empty) == "b''"

    b = SecretStr("abc")
    assert str(b) == "**********"

    b_empty = SecretStr("")
    assert str(b_empty) == ""


def test_len():
    a = SecretBytes(b"abc")
    assert len(a) == 3

    b = SecretStr("abc")
    assert len(b) == 3


def test_randomness(no_random_randbytes: None, n: int = 16):
    data = randbytes(n)
    assert data == bytes(range(1, n + 1))
    assert isinstance(data, bytes)
    assert len(data) == n


def test_salt():
    assert Salt(b"\x00" * 16) == Salt(b"\x00" * 16)
    assert Salt(b"\x00" * 16) != Salt(b"\x01" * 16)
    assert bytes(Salt(b"\x00" * 16)) == b"\x00" * 16
    assert len(Salt(b"\x00" * 16)) == 16


def test_cipher_key():
    assert CipherKey(b"\x00" * 16).get_secret_value() == CipherKey.fromhex("00" * 16).get_secret_value()
    assert CipherKey(b"\x00" * 16).get_secret_value() != CipherKey(b"\x01" * 16).get_secret_value()


def test_iv():
    assert IV(b"\x00" * 16).get_secret_value() == IV.fromhex("00" * 16).get_secret_value()
    assert IV(b"\x00" * 16).get_secret_value() != IV(b"\x01" * 16).get_secret_value()


def test_encrypted_bytes():
    a = EncryptedBytes(b"abc")
    b = EncryptedBytes(b"abc")
    c = EncryptedBytes(b"def")
    assert a == b
    assert a != c
    assert hash(a) == hash(b)
    assert hash(a) != hash(c)
    assert bytes(a) == a.value
    assert a.fromhex("616263") == a
    assert len(a) == 3
