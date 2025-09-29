import dataclasses
from ctypes import c_uint32
from typing import Annotated, ClassVar

import ssh_proto_types
from ssh_proto_types import Packet as SSHPacket

# Magic Key Format:
b"openssh-key-v1\x00"

# Header Fields
# CipherName
b"\x00\x00\x00\x04"
b"none"
# KDFName
b"\x00\x00\x00\x04"
b"none"
# KDFOptions
b"\x00\x00\x00\x00"
# Number of keys (1)
b"\x00\x00\x00\x01"
# Public Key
b"\x00\x00\x003"  # 51
b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 V,4j\xc8\xa8\x86\xea\xa5w\xcd\x8f}a0\x98\xfd+\x98f\x03\x1f\xb8B\x0f\xae\x8b03\x07\x9b\x01"
# Private Key Block
b"\x00\x00\x00\xa0"  # 160
b"%\x92u\xae%\x92u\xae\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 V,4j\xc8\xa8\x86\xea\xa5w\xcd\x8f}a0\x98\xfd+\x98f\x03\x1f\xb8B\x0f\xae\x8b03\x07\x9b\x01\x00\x00\x00@\x8e\x03~\xac\xf0l\xba\xdd@\x91\xbd#@$\xed\xdbj\xed\xc1\xc4\xe4\xf7\x84\x02\xf0\x9f\x8b\xd0\xd8\xba\xbf(V,4j\xc8\xa8\x86\xea\xa5w\xcd\x8f}a0\x98\xfd+\x98f\x03\x1f\xb8B\x0f\xae\x8b03\x07\x9b\x01\x00\x00\x00\x12eddsa-key-20250924\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b"

MAGIC_HEADER = b"openssh-key-v1\x00"


def can_parse(data: bytes) -> bool:
    return data.startswith(MAGIC_HEADER)


def parse_file(data: bytes):
    data = data[len(MAGIC_HEADER) :]
    return ssh_proto_types.unmarshal(OpenSSHEncryptedPrivateKeyFile, data)


class OpenSSHPublicKey(SSHPacket):
    key_type: ClassVar[str]


class OpenSSHPublicKeyRSA(OpenSSHPublicKey):
    key_type: ClassVar[str] = "ssh-rsa"
    e: int
    n: int


class OpenSSHPublicKeyEd25519(OpenSSHPublicKey):
    key_type: ClassVar[str] = "ssh-ed25519"
    pub: bytes


class OpenSSHPrivateKey(SSHPacket):
    check_int_1: Annotated[int, c_uint32]
    check_int_2: Annotated[int, c_uint32]
    key_type: ClassVar[str]

    def __post_init__(self):
        self.validate()

    def validate(self):
        if self.check_int_1 != self.check_int_2:
            raise ValueError("Check integers do not match")


class OpenSSHEd25519PrivateKey(OpenSSHPrivateKey):
    key_type: ClassVar[str] = "ssh-ed25519"
    pub: bytes
    priv: bytes
    comment: str
    pad: bytes

    def validate(self):
        super().validate()
        if len(self.pub) != 32:
            raise ValueError("Invalid public key length")
        if len(self.priv) != 64:
            raise ValueError("Invalid private key length")
        if self.priv[32:] != self.pub:
            raise ValueError("Private key does not match public key")


@dataclasses.dataclass
class OpenSSHRSAPrivateKey(SSHPacket):
    key_type: ClassVar[str] = "ssh-rsa"
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    comment: str
    pad: bytes


@dataclasses.dataclass
class OpenSSHEncryptedPrivateKeyFile(SSHPacket):
    cipher_name: str
    kdf_name: str
    kdf_opts: bytes
    n_keys: Annotated[int, c_uint32]
    pub_keys: bytes
    priv_keys: bytes

    def public_key(self):
        return ssh_proto_types.unmarshal(OpenSSHPublicKey, self.pub_keys)

    def private_key(self):
        return ssh_proto_types.unmarshal(OpenSSHPrivateKey, self.priv_keys)
