from ssh_key_mgr.secretstr import SecretBytes, SecretStr


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
