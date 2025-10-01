import os
import struct
from typing import Annotated, ClassVar, Self

import ssh_proto_types as spt

from ssh_key_mgr import pem
from ssh_key_mgr.openssh import encryption as enc
from ssh_key_mgr.openssh.aes import EncryptedBytes
from ssh_key_mgr.openssh.bcrypt import Rounds, Salt
from ssh_key_mgr.secretstr import SecretBytes

PEM_HEADER = "OPENSSH PRIVATE KEY"

AES256_CTR = "aes256-ctr"
BCRYPT = "bcrypt"
NONE = "none"

SSH_ED25519 = "ssh-ed25519"
SSH_RSA = "ssh-rsa"

MAGIC_HEADER = b"openssh-key-v1\x00"


def _random_uint32() -> int:
    return struct.unpack(">I", os.urandom(4))[0]


class OpenSSHPublicKey(spt.Packet):
    key_type: ClassVar[str]


class OpenSSHPublicKeyRSA(OpenSSHPublicKey):
    key_type: ClassVar[str] = SSH_RSA
    e: int
    n: int


class OpenSSHPublicKeyEd25519(OpenSSHPublicKey):
    key_type: ClassVar[str] = SSH_ED25519
    value: bytes


class OpenSSHCheck(spt.Packet):
    check_int_1: Annotated[int, spt.c_uint32]
    check_int_2: Annotated[int, spt.c_uint32]

    def __post_init__(self):
        self.validate()

    @classmethod
    def create(cls, value: int | None) -> Self:
        if value is None:
            value = _random_uint32()
        return cls(check_int_1=value, check_int_2=value)

    def validate(self):
        if self.check_int_1 != self.check_int_2:
            raise ValueError("Check integers do not match")


class OpenSSHPrivateKey(spt.Packet):
    check: OpenSSHCheck
    key_type: ClassVar[str]


class OpenSSHEd25519PrivateKey(OpenSSHPrivateKey):
    key_type: ClassVar[str] = SSH_ED25519
    public: bytes
    private: bytes
    comment: str

    def __post_init__(self):
        self.validate()

    def validate(self):
        if len(self.public) != 32:
            raise ValueError("Invalid public key length")
        if len(self.private) != 64:
            raise ValueError("Invalid private key length")
        if self.private[32:] != self.public:
            raise ValueError("Private key does not end with public key")


class OpenSSHRSAPrivateKey(OpenSSHPrivateKey):
    key_type: ClassVar[str] = SSH_RSA
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    comment: str


class EncryptedPrivateFile(spt.Packet):
    cipher_name: ClassVar[str]

    def private_key(self, passphrase: SecretBytes | None) -> OpenSSHPrivateKey:
        raise NotImplementedError


class KDFOptions(spt.Packet):
    salt: Annotated[Salt, bytes]
    rounds: Annotated[Rounds, spt.c_uint32]


class EncryptedPrivateFilePlain(EncryptedPrivateFile):
    cipher_name: ClassVar[str] = NONE
    kdf_name: ClassVar[str] = NONE
    kdf_opts: ClassVar[bytes] = b""
    n_keys: ClassVar[Annotated[int, spt.c_uint32]] = 1
    public_key: Annotated[OpenSSHPublicKey, spt.nested]
    encrypted_private_key: Annotated[EncryptedBytes, bytes]

    def private_key(self, passphrase: SecretBytes | None) -> OpenSSHPrivateKey:
        if passphrase is not None and passphrase.get_secret_value() != b"":
            raise ValueError("Passphrase should not be provided for unencrypted private key")
        return enc.decrypt_plain(OpenSSHPrivateKey, self.encrypted_private_key)


class EncryptedPrivateFileAes256(EncryptedPrivateFile):
    cipher_name: ClassVar[str] = AES256_CTR
    kdf_name: ClassVar[str] = BCRYPT
    kdf_opts: Annotated[KDFOptions, spt.nested]
    n_keys: ClassVar[Annotated[int, spt.c_uint32]] = 1
    public_key: Annotated[OpenSSHPublicKey, spt.nested]

    encrypted_private_key: Annotated[EncryptedBytes, bytes]

    def private_key(self, passphrase: SecretBytes | None) -> OpenSSHPrivateKey:
        if passphrase is None:
            raise ValueError("Passphrase is required for encrypted private key")
        return enc.decrypt_aes256_ctr_bcrypt(
            OpenSSHPrivateKey,
            self.encrypted_private_key,
            passphrase=passphrase,
            rounds=self.kdf_opts.rounds,
            salt=self.kdf_opts.salt,
        )


def can_parse_data(data: bytes) -> bool:
    return data.startswith(MAGIC_HEADER)


def decode_data(data: bytes):
    data = data[len(MAGIC_HEADER) :]
    return spt.unmarshal(EncryptedPrivateFile, data)


def encode_data(obj: EncryptedPrivateFile) -> bytes:
    return MAGIC_HEADER + spt.marshal(obj)


def can_parse_pem(block: pem.PEMBlock) -> bool:
    return block.header == PEM_HEADER and block.footer == PEM_HEADER


def decode_pem(block: pem.PEMBlock) -> EncryptedPrivateFile:
    if block.header != PEM_HEADER or block.footer != PEM_HEADER:
        raise ValueError(f"Invalid PEM header/footer, expected {PEM_HEADER}")
    return decode_data(block.data)


def encode_pem(obj: EncryptedPrivateFile) -> pem.PEMBlock:
    return pem.PEMBlock(
        header=PEM_HEADER,
        footer=PEM_HEADER,
        data=encode_data(obj),
    )


def can_parse_file(data: bytes) -> bool:
    return data.startswith(f"-----BEGIN {PEM_HEADER}-----".encode()) and data.rstrip().endswith(
        f"-----END {PEM_HEADER}-----".encode()
    )


def encode_file(obj: EncryptedPrivateFile) -> bytes:
    return pem.marshal(
        encode_pem(obj),
        width=70,
        use_spaces=False,
    )


def decode_file(data: bytes) -> EncryptedPrivateFile:
    blocks = pem.unmarshal(data)
    if len(blocks) != 1:
        raise ValueError("Expected exactly one PEM block")
    block = blocks[0]
    return decode_pem(block)
