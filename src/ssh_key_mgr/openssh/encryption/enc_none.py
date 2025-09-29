import dataclasses
from typing import Annotated, ClassVar, override

import ssh_proto_types as spt

from ssh_key_mgr.encryption import EncryptedBytes, SecretBytes
from ssh_key_mgr.openssh.encryption.base import DecryptionParams, Encryption, EncryptionParams

ENCRYPTION_NAME = "none"
KDEF_NAME = "none"
BLOCK_SIZE = 16  # Should be 8, but OpenSSH uses 16 for none too
REQUIRE_PASSPHRASE = False


class KDFOptionsNone(spt.Packet):
    pass


class DecryptionParamsNone(DecryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_NAME
    kdf_name: ClassVar[str] = KDEF_NAME
    kdf_opts: ClassVar[Annotated[KDFOptionsNone, spt.nested]] = KDFOptionsNone()

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @property
    @override
    def block_size(self) -> int:
        return BLOCK_SIZE

    @override
    def _decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> bytes:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError("Passphrase should not be provided for unencrypted private key")
        return bytes(encrypted)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class EncryptionParamsNone(EncryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_NAME

    @property
    @override
    def block_size(self) -> int:
        return BLOCK_SIZE

    @override
    def _encrypt(self, decrypted: bytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, DecryptionParams]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError("Passphrase should not be provided for unencrypted private key")
        return EncryptedBytes(decrypted), DecryptionParamsNone()


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class EncryptionNone(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @override
    def generate_params(self) -> EncryptionParamsNone:
        return EncryptionParamsNone()
