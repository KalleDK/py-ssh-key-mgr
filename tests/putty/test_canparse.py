from ssh_key_mgr import putty


def test_can_parse():
    assert putty.can_parse(b"PuTTY-User-Key-File-3: something")
    assert putty.can_parse(b"PuTTY-User-Key-File-2: something")
    assert putty.can_parse(b"PuTTY-User-Key-File-1: something")
    assert not putty.can_parse(b"something else")
