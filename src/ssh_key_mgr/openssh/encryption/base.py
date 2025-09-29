import abc
import dataclasses
from typing import Annotated, ClassVar, Self

import ssh_proto_types
import ssh_proto_types as spt

from ssh_key_mgr.encryption import EncryptedBytes, SecretBytes, gen_random_uint32
from ssh_key_mgr.openssh.encryption import aes as aes
from ssh_key_mgr.openssh.keys import OpenSSHPrivateKey


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


class DecryptionParams(spt.Packet):
    cipher_name: ClassVar[str]

    @property
    @abc.abstractmethod
    def require_passphrase(self) -> bool:
        raise NotImplementedError

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


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Encryption:
    cipher_name: ClassVar[str]

    @property
    @abc.abstractmethod
    def require_passphrase(self) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def generate_params(self) -> EncryptionParams:
        raise NotImplementedError()
