import abc
import dataclasses
import enum
from typing import ClassVar, Self, cast, override

import ssh_proto_types as spt

from ssh_key_mgr.putty import ppk
from ssh_key_mgr.putty.checksum import Mac, MacData
from ssh_key_mgr.putty.encryption import (
    DecryptionParams,
    EncryptedBytes,
    EncryptionParams,
)
from ssh_key_mgr.putty.keys import (
    PuttyKey,
    PuttyPublicKey,
)
from ssh_key_mgr.putty.ppk.stream import BytesField, HexField, StrField
from ssh_key_mgr.secretstr import SecretBytes

# region Putty File


class PuttyFormatVersion(enum.StrEnum):
    V3 = "PuTTY-User-Key-File-3"
    V2 = "PuTTY-User-Key-File-2"
    V1 = "PuTTY-User-Key-File-1"


def can_parse(data: bytes) -> bool:
    for v in PuttyFormatVersion:
        if data.startswith(v.value.encode()):
            return True
    return False


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyFile:
    file_version: ClassVar[PuttyFormatVersion]
    __child: ClassVar[dict[PuttyFormatVersion, type["PuttyFile"]]] = {}

    def __init_subclass__(cls) -> None:
        cls.__child[cls.file_version] = cls

    @abc.abstractmethod
    def get_public_key_unverified(self) -> PuttyPublicKey:
        raise NotImplementedError()

    @abc.abstractmethod
    def decrypt(self, passphrase: SecretBytes | None) -> PuttyKey:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def unmarshal_ppk_part(cls, stream: ppk.StreamReader) -> Self:
        raise NotImplementedError("unmarshal_ppk_part must be implemented in subclasses")

    @classmethod
    def unmarshal_ppk(cls, stream: ppk.StreamReader) -> Self:
        file_version = PuttyFormatVersion(stream.read_named_str("File-Version"))
        if file_version not in cls.__child:
            raise ValueError(f"Unsupported file version {file_version}")
        return cast(Self, cls.__child[file_version].unmarshal_ppk_part(stream))

    @abc.abstractmethod
    def marshal_ppk(self, stream: ppk.StreamWriter) -> None:
        raise NotImplementedError("marshal_ppk must be implemented in subclasses")


class PuttyFileV1(PuttyFile):
    file_version: ClassVar[PuttyFormatVersion] = PuttyFormatVersion.V1

    @classmethod
    def unmarshal_ppk_part(cls, stream: ppk.StreamReader) -> "PuttyFile":
        raise NotImplementedError("PuttyFileV1 is not implemented")


class PuttyFileV2(PuttyFile):
    file_version: ClassVar[PuttyFormatVersion] = PuttyFormatVersion.V2

    @classmethod
    def unmarshal_ppk_part(cls, stream: ppk.StreamReader) -> "PuttyFile":
        raise NotImplementedError("PuttyFileV2 is not implemented")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyFileV3(PuttyFile):
    file_version: ClassVar[PuttyFormatVersion] = PuttyFormatVersion.V3
    key_type: str
    comment: str
    decryption_params: DecryptionParams
    public_lines: bytes
    private_lines: EncryptedBytes
    mac: Mac

    @classmethod
    def encrypt(cls, key: PuttyKey, encryption_params: EncryptionParams, passphrase: SecretBytes | None) -> Self:
        private_wire = bytes(key.private)
        private_padded_wire = encryption_params.add_padding(private_wire)
        private_lines, decryption_params, mac_key = encryption_params.encrypt(private_padded_wire, passphrase)
        public_wire = bytes(key.public)
        mac = Mac.generate(
            data=MacData(
                algorithm=key.key_type,
                encryption=decryption_params.encryption_type,
                comment=key.comment,
                public_wire=public_wire,
                private_padded_wire=private_padded_wire,
            ),
            key=mac_key,
        )
        return cls(
            key_type=key.key_type,
            comment=key.comment,
            public_lines=public_wire,
            decryption_params=decryption_params,
            private_lines=private_lines,
            mac=mac,
        )

    def decrypt(self, passphrase: SecretBytes | None) -> PuttyKey:
        decrypted, mac_key = self.decryption_params.decrypt(self.private_lines, passphrase)

        self.mac.validate(
            MacData(
                algorithm=self.key_type,
                encryption=self.decryption_params.encryption_type,
                comment=self.comment,
                public_wire=self.public_lines,
                private_padded_wire=decrypted,
            ),
            key=mac_key,
        )

        return PuttyKey.unmarshal(
            key_type=self.key_type,
            public_key=self.public_lines,
            private_key=decrypted,
            comment=self.comment,
        )

    def get_public_key_unverified(self) -> PuttyPublicKey:
        return spt.unmarshal(PuttyPublicKey, self.public_lines)

    @override
    def marshal_ppk(self, stream: ppk.StreamWriter) -> None:
        stream.write_str(StrField(name="File-Version", value=self.file_version.value))
        stream.write_str(StrField(name="Key-Type", value=self.key_type))
        stream.write_str(StrField(name="Encryption", value=self.decryption_params.encryption_type))
        stream.write_str(StrField(name="Comment", value=self.comment))
        stream.write_bytes(BytesField(name="Public-Lines", value=self.public_lines))
        self.decryption_params.marshal_ppk_part(stream)
        stream.write_bytes(BytesField(name="Private-Lines", value=bytes(self.private_lines)))
        stream.write_hexbytes(HexField(name="Private-MAC", value=self.mac.private_mac))

    @override
    @classmethod
    def unmarshal_ppk_part(cls, stream: ppk.StreamReader) -> Self:
        key_type = stream.read_named_str("Key-Type")
        encryption = stream.read_named_str("Encryption")
        comment = stream.read_named_str("Comment")
        public_lines = stream.read_named_bytes("Public-Lines")
        encryption_params = DecryptionParams.unmarshal_ppk_part(encryption, stream)
        private_lines = EncryptedBytes(stream.read_named_bytes("Private-Lines"))
        mac = Mac(private_mac=stream.read_named_hexbytes("Private-MAC"))

        return cls(
            key_type=key_type,
            comment=comment,
            public_lines=public_lines,
            decryption_params=encryption_params,
            private_lines=private_lines,
            mac=mac,
        )

    @override
    @classmethod
    def unmarshal_ppk(cls, stream: ppk.StreamReader) -> Self:
        file_version = PuttyFormatVersion(stream.read_named_str("File-Version"))
        if file_version != cls.file_version:
            raise ValueError(f"Expected file version {cls.file_version}, got {file_version}")
        return cls.unmarshal_ppk_part(stream)


# endregion
