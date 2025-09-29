import dataclasses

from ssh_key_mgr.secretstr import SecretBytes


@dataclasses.dataclass(frozen=True, slots=True, eq=True, repr=True)
class _bytes:
    value: bytes

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)


class EncryptedBytes(_bytes):
    pass


class IV(SecretBytes):
    pass


class CipherKey(SecretBytes):
    pass


class Nonce(SecretBytes):
    pass
