import hashlib
import hmac
from typing import Annotated, Self, SupportsBytes

import ssh_proto_types as spt

from ssh_key_mgr.encryption import SecretBytes
from ssh_key_mgr.putty import ppk


class MacKey(SecretBytes):
    pass


class MacData(spt.Packet):
    algorithm: str
    encryption: str
    comment: str
    public_wire: bytes
    private_padded_wire: bytes


class Mac(ppk.File):
    private_mac: Annotated[bytes, ppk.hexbytes]

    @classmethod
    def generate(cls, data: SupportsBytes, key: MacKey) -> Self:
        mac = hmac.new(
            key.get_secret_value(),
            msg=bytes(data),
            digestmod=hashlib.sha256,
        ).digest()
        return cls(private_mac=mac)

    def validate(self, data: SupportsBytes, key: MacKey):
        expected = Mac.generate(data, key)
        if not hmac.compare_digest(self.private_mac, expected.private_mac):
            raise ValueError("MAC validation failed")


# endregion
