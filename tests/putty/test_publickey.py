import pytest
import ssh_proto_types as spt

from ssh_key_mgr.putty import PuttyPublicKey

from .data import PUTTY_KEY_NAMES, PUTTY_PUBLIC_KEY_WIRES, PUTTY_PUBLIC_KEYS


@pytest.mark.parametrize("key_name", PUTTY_KEY_NAMES)
def test_specific_public_unmarshal(
    key_name: str,
):
    want = PUTTY_PUBLIC_KEYS[key_name]
    key_cls = want.__class__
    key_wire = PUTTY_PUBLIC_KEY_WIRES[key_name]
    got = spt.unmarshal(key_cls, key_wire)
    assert got == want


@pytest.mark.parametrize("key_name", PUTTY_KEY_NAMES)
def test_public_unmarshal(key_name: str):
    want = PUTTY_PUBLIC_KEYS[key_name]
    key_wire = PUTTY_PUBLIC_KEY_WIRES[key_name]
    got = spt.unmarshal(PuttyPublicKey, key_wire)
    assert got == want


@pytest.mark.parametrize("key_name", PUTTY_KEY_NAMES)
def test_public_key_marshal(key_name: str):
    want = PUTTY_PUBLIC_KEY_WIRES[key_name]
    got = spt.marshal(PUTTY_PUBLIC_KEYS[key_name])
    assert got == want


def test_public_key_marshal_fails():
    key = PuttyPublicKey()
    with pytest.raises(ValueError):
        spt.marshal(key)
