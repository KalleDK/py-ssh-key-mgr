import dataclasses
import inspect

import pytest

from ssh_key_mgr.encryption import Rounds, Salt, SecretBytes
from ssh_key_mgr.openssh.encryption.bcrypt import hash_passphrase
from tests.conftest import mark_skip_if_bcrypt_missing


@dataclasses.dataclass
class GenSaltCase:
    size: int
    expected: bytes


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


@mark_skip_if_bcrypt_missing
def test_signature():
    from ssh_key_mgr.openssh.encryption.bcrypt import impl, stub

    got = inspect.signature(impl.hash_passphrase)

    want = inspect.signature(stub.hash_passphrase)
    assert got.return_annotation == want.return_annotation
    assert got.parameters == want.parameters


@mark_skip_if_bcrypt_missing
@pytest.mark.parametrize("case", hash_passphrase_cases)
def test_hash_passphrase(case: HashPassphraseCase) -> None:
    got = hash_passphrase(case.passphrase, case.hash_len, case.rounds, case.salt)
    assert isinstance(got, bytes)
    assert len(got) == case.hash_len
    assert got == case.want
