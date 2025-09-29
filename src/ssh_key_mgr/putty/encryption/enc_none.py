import dataclasses
from typing import ClassVar, SupportsBytes, override

from ssh_key_mgr.encryption import (
    EncryptedBytes,
    SecretBytes,
)
from ssh_key_mgr.putty import ppk
from ssh_key_mgr.putty.checksum import MacKey
from ssh_key_mgr.putty.encryption.base import DecryptionParams, Encryption, EncryptionParams

# region Encryption NONE

ENCRYPTION_NAME = "none"
REQUIRE_PASSPHRASE = False
BLOCK_SIZE = 1


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Decryption_NONE_Params(DecryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> "Decryption_NONE_Params":
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")
        return Decryption_NONE_Params()

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for decryption of {self.encryption_type}")
        return bytes(data), MacKey(b"")

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        pass


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_NONE_Params(EncryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @property
    @override
    def block_size(self) -> int:
        return BLOCK_SIZE

    @override
    def _encrypt(
        self, decrypted: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, Decryption_NONE_Params, MacKey]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError(f"Passphrase must not be set for encryption with {ENCRYPTION_NAME}")
        return EncryptedBytes(bytes(decrypted)), Decryption_NONE_Params(), MacKey(b"")


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_NONE(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @override
    def generate_params(self) -> "Encryption_NONE_Params":
        return Encryption_NONE_Params()


# endregion
