import dataclasses
from unittest.mock import patch

import pytest

from ssh_key_mgr.openssh.bcrypt import Rounds, Salt, gen_salt, hash_passphrase
from ssh_key_mgr.secretstr import SecretBytes


@dataclasses.dataclass
class GenSaltCase:
    size: int
    expected: bytes


@pytest.mark.parametrize("case", [GenSaltCase(16, b"abcdefghijklmnop"), GenSaltCase(22, b"abcdefghijklmnopqrstuv")])
def test_gen_salt(case: GenSaltCase) -> None:
    with patch("bcrypt.gensalt") as mock_gensalt:
        mock_gensalt.return_value = b"$2b$12$abcdefghijklmnopqrstuv"
        salt = gen_salt(case.size)
        mock_gensalt.assert_called_once_with(prefix=b"2b", rounds=12)

    assert isinstance(salt, Salt)
    assert bytes(salt) == case.expected
    assert len(salt) == case.size


def test_gen_salt_invalid_size() -> None:
    with pytest.raises(AssertionError, match="SALT_SIZE must be <= 22"):
        gen_salt(23)
    with pytest.raises(AssertionError, match="SALT_SIZE must be > 0"):
        gen_salt(0)


@dataclasses.dataclass
class HashPassphraseCase:
    passphrase: SecretBytes
    hash_len: int
    salt: Salt
    rounds: Rounds
    want: bytes


hash_passphrase_cases = [
    HashPassphraseCase(
        SecretBytes(b"password"),
        32,
        Salt(b"abcdefghijklmnop"),
        Rounds(12),
        b"J_,_\xaeC\xd0\xe8\xa2\x8d#Oa\xc8\x93\n\x1f`\xbd{{\xda\xd7BJ\xac\x83_`\x98\x94\xb8",
    ),
    HashPassphraseCase(
        SecretBytes(b"demo"),
        48,
        Salt(b"1234567890abcdef"),
        Rounds(8),
        b'"\x05\xe7\xc7\xe6\x0c]\x97\xc0.fW\xaa\xbd\x07\xf1\xe3\x07\x94.\x98\x11\xfe\xe4-\xe3\xcdT^\xc2gP\x96\xd8\xf3\x9a\xcf\x132\x05\x15nZ\x94s\xaf\xdd\xcb',
    ),
    HashPassphraseCase(
        SecretBytes(b"another_password"),
        64,
        Salt(b"qrstuvwxyzabcdef"),
        Rounds(16),
        b"k+\xfb@\xe7\x0f$\xde=\xab_\xe0x\x96\xb0k\xaf[\xe4h\xab\x87\x9db\xa1\xcb.\\jt\x0b\xdc\x8ca\x1b\xf4\x88/\xd08\xbe\xc0\xe2\xfe\xe5\xf6a`\x98/\x88\xeb\x1c\run\xe6\xcb\xe9\x83\x94Q\x01\x94",
    ),
]


@pytest.mark.parametrize("case", hash_passphrase_cases)
def test_hash_passphrase(case: HashPassphraseCase) -> None:
    got = hash_passphrase(case.passphrase, case.hash_len, case.rounds, case.salt)
    assert isinstance(got, bytes)
    assert len(got) == case.hash_len
    assert got == case.want
