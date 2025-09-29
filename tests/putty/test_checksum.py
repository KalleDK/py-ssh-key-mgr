import pytest

from ssh_key_mgr.putty.checksum import Mac, MacKey


def test_mac_generation():
    want = Mac(
        private_mac=b'cu\x05+\xe3\xd7\t\xab\xd2\x89"\x87\xaa5\x03\xb2\x08\xf0\xf9P\x8bx\xe7v@\xe4\xa6\x02\x00\xc5h\xe1'
    )
    data = b"hello, world"
    key = MacKey(bytes.fromhex("0102"))
    got = Mac.generate(data, key=key)
    assert got == want


def test_mac_validation():
    mac = Mac(
        private_mac=b'cu\x05+\xe3\xd7\t\xab\xd2\x89"\x87\xaa5\x03\xb2\x08\xf0\xf9P\x8bx\xe7v@\xe4\xa6\x02\x00\xc5h\xe1'
    )
    data = b"hello, world"
    key = MacKey(bytes.fromhex("0102"))
    mac.validate(data, key=key)


def test_mac_invalid_mac():
    mac = Mac(
        private_mac=b'cu\x05+\xe3\xd7\t\xab\xd2\x89"\x87\xaa5\x03\xb2\x08\xf0\xf9P\x8bx\xe7v@\xe4\xa6\x02\x00\xc5h\xe2'
    )
    data = b"hello, world"
    key = MacKey(bytes.fromhex("0102"))
    with pytest.raises(ValueError):
        mac.validate(data, key=key)
