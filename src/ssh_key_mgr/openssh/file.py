from typing import Annotated, ClassVar, Self

import ssh_proto_types as spt

from ssh_key_mgr import pem
from ssh_key_mgr.openssh.encryption import DecryptionParams, EncryptedBytes, EncryptionParams
from ssh_key_mgr.openssh.keys import OpenSSHKeyPair, OpenSSHPublicKey
from ssh_key_mgr.secretstr import SecretBytes

PEM_HEADER = "OPENSSH PRIVATE KEY"

MAGIC_HEADER = b"openssh-key-v1\x00"


class EncryptedPrivateFile(spt.Packet):
    decryption_params: DecryptionParams
    n_keys: ClassVar[Annotated[int, spt.c_uint32]] = 1
    public_key: Annotated[OpenSSHPublicKey, spt.nested]
    encrypted_private_key: Annotated[EncryptedBytes, bytes]

    def decrypt(self, passphrase: SecretBytes | None) -> OpenSSHKeyPair:
        private_key = self.decryption_params.decrypt(self.encrypted_private_key, passphrase)
        return OpenSSHKeyPair.unmarshal(self.public_key, private_key)

    @classmethod
    def encrypt(
        cls,
        key_pair: OpenSSHKeyPair,
        params: EncryptionParams,
        passphrase: SecretBytes | None,
    ) -> Self:
        encrypted, decryption_params = params.encrypt(key_pair.private, passphrase)

        return cls(
            decryption_params=decryption_params,
            public_key=key_pair.public,
            encrypted_private_key=encrypted,
        )


# region General Functions


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


# endregion
