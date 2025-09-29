from typing import Protocol

from ssh_key_mgr.encryption import SecretBytes
from ssh_key_mgr.keys import KeyPairProto


class EncryptedFile(Protocol):
    @property
    def require_passphrase(self) -> bool: ...

    def decrypt(self, passphrase: SecretBytes | None) -> KeyPairProto: ...
