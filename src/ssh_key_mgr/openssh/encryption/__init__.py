import abc
import dataclasses
import random
import struct
from typing import Annotated, ClassVar, Self, override

import ssh_proto_types
import ssh_proto_types as spt

from ssh_key_mgr.openssh.encryption import enc_aes256_ctr_bcrypt, enc_plain
from ssh_key_mgr.openssh.encryption.aes import EncryptedBytes
from ssh_key_mgr.openssh.encryption.bcrypt import Rounds, Salt, gen_salt
from ssh_key_mgr.openssh.keys import OpenSSHPrivateKey
from ssh_key_mgr.secretstr import SecretBytes

# region Helpers


def gen_random_uint32() -> int:
    return struct.unpack(">I", random.randbytes(4))[0]


# endregion


class OpenSSHCheck(spt.Packet):
    check_int_1: Annotated[int, spt.c_uint32]
    check_int_2: Annotated[int, spt.c_uint32]

    def __post_init__(self):
        self.validate()

    @classmethod
    def create(cls, value: int | None = None) -> Self:
        if value is None:
            value = gen_random_uint32()
        return cls(check_int_1=value, check_int_2=value)

    def validate(self):
        if self.check_int_1 != self.check_int_2:
            raise ValueError("Check integers do not match")


class Payload(spt.Packet):
    check: OpenSSHCheck
    private: OpenSSHPrivateKey


def attach_padding(stream: ssh_proto_types.StreamWriter, block_size: int) -> None:
    padding = (block_size - len(stream) % block_size) % block_size  # padding
    if padding > 0:
        stream.write_raw(bytes(range(1, padding + 1)))


def verify_padding(stream: ssh_proto_types.StreamReader, block_size: int) -> None:
    padding = (block_size - stream.amount_read() % block_size) % block_size  # padding
    if padding > 0:
        pad_bytes = stream.read_raw(padding)
        if pad_bytes != bytes(range(1, padding + 1)):
            raise ValueError("Invalid padding")
    assert stream.eof()


# region Encryption Params Base


class DecryptionParams(spt.Packet):
    cipher_name: ClassVar[str]

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def _decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> bytes:
        raise NotImplementedError

    def decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> OpenSSHPrivateKey:
        decrypted = self._decrypt(encrypted, passphrase)
        stream = spt.StreamReader(decrypted)

        obj = spt.unmarshal(Payload, data=stream)
        verify_padding(stream, self.block_size)
        return obj.private


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class EncryptionParams:
    cipher_name: ClassVar[str]

    @property
    @abc.abstractmethod
    def block_size(self) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def _encrypt(self, decrypted: bytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, DecryptionParams]:
        raise NotImplementedError

    def encrypt(
        self, private: OpenSSHPrivateKey, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, DecryptionParams]:
        stream = spt.StreamWriter()
        payload = Payload(check=OpenSSHCheck.create(None), private=private)
        spt.marshal(payload, stream)
        attach_padding(stream, self.block_size)
        return self._encrypt(stream.get_bytes(), passphrase)


# endregion

# region Encryption Params None

ENCRYPTION_NONE = "none"
KDEF_NONE = "none"


class KDFOptionsNone(spt.Packet):
    pass


class DecryptionParamsNone(DecryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_NONE
    kdf_name: ClassVar[str] = KDEF_NONE
    kdf_opts: ClassVar[Annotated[KDFOptionsNone, spt.nested]] = KDFOptionsNone()

    @property
    @override
    def block_size(self) -> int:
        return enc_plain.BLOCK_SIZE

    @override
    def _decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> bytes:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError("Passphrase should not be provided for unencrypted private key")
        return bytes(encrypted)


class EncryptionParamsNone(EncryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_NONE

    @property
    @override
    def block_size(self) -> int:
        return enc_plain.BLOCK_SIZE

    @override
    def _encrypt(self, decrypted: bytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, DecryptionParams]:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError("Passphrase should not be provided for unencrypted private key")
        return EncryptedBytes(decrypted), DecryptionParamsNone()


# endregion

# region Encryption Params AES256-CTR + Bcrypt KDF

ENCRYPTION_AES256_CTR = "aes256-ctr"
KDEF_BCRYPT = "bcrypt"


class KDFOptions(spt.Packet):
    salt: Annotated[Salt, bytes]
    rounds: Annotated[Rounds, spt.c_uint32]


class DecryptionParamsAes256(DecryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_AES256_CTR
    kdf_name: ClassVar[str] = KDEF_BCRYPT
    kdf_opts: Annotated[KDFOptions, spt.nested]

    @property
    @override
    def block_size(self) -> int:
        return enc_aes256_ctr_bcrypt.BLOCK_SIZE

    @override
    def _decrypt(self, encrypted: EncryptedBytes, passphrase: SecretBytes | None) -> bytes:
        if passphrase is None:
            raise ValueError("Passphrase is required for encrypted private key")
        return enc_aes256_ctr_bcrypt.decrypt(
            encrypted,
            passphrase=passphrase,
            rounds=self.kdf_opts.rounds,
            salt=self.kdf_opts.salt,
        )


class EncryptionParamsAes256(EncryptionParams):
    cipher_name: ClassVar[str] = ENCRYPTION_AES256_CTR
    rounds: Rounds = enc_aes256_ctr_bcrypt.DEFAULT_ROUNDS
    salt_length: int = enc_aes256_ctr_bcrypt.SALT_SIZE

    @property
    @override
    def block_size(self) -> int:
        return enc_aes256_ctr_bcrypt.BLOCK_SIZE

    @override
    def _encrypt(self, decrypted: bytes, passphrase: SecretBytes | None) -> tuple[EncryptedBytes, DecryptionParams]:
        if passphrase is None:
            raise ValueError("Passphrase is required for encrypted private key")
        salt = gen_salt(self.salt_length)
        encrypted = enc_aes256_ctr_bcrypt.encrypt(decrypted, passphrase=passphrase, salt=salt, rounds=self.rounds)

        return encrypted, DecryptionParamsAes256(kdf_opts=KDFOptions(salt=salt, rounds=self.rounds))


# endregion


__all__ = [
    "Salt",
    "Rounds",
    "SecretBytes",
    "EncryptedBytes",
]
