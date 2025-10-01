import pytest

from ssh_key_mgr import pem

PEM_FILE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAsNGDUqiPU9VRb0bCDno2fX3ois9UoBn23vV6ubRM7dsiQrG8oPsb
XLgrMDYXamOQNWTexutB2y+Px4f05S4RSeMzR1cpc/Zgw8d8qeCCHCtpW+eunX0w9AeREP
SKrm+LcC1HSykAgX8oZiSb7BKisZuCeEFoCPga4fz5t3eKYj8AAAIQB1vNFQdbzRUAAAAH
c3NoLXJzYQAAAIEAsNGDUqiPU9VRb0bCDno2fX3ois9UoBn23vV6ubRM7dsiQrG8oPsbXL
grMDYXamOQNWTexutB2y+Px4f05S4RSeMzR1cpc/Zgw8d8qeCCHCtpW+eunX0w9AeREPSK
rm+LcC1HSykAgX8oZiSb7BKisZuCeEFoCPga4fz5t3eKYj8AAAADAQABAAAAgEgun4+k5C
3zDXWBy0KhvZDpT38rOH7LWq6WQ+1/n1ASfx/+8uQ83mSxgmACFPkHgB1r+k32SEI0Xlu0
MtNERSXYMBZUxUQrCl4RucfiAfoy9Bq69PCm4Dzw4MuCZsYq0R2VbVPJRm5ImV/qJgyFNv
BByzVi+qxRHE1mqP7REbKRAAAAQQC5nX+PTU1FXx+6Ri2ZCi6EjEKMHr7gHcABhMinZYOt
N59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3gi27bAAAAQQDp2G5Nw0qYWn7HWm9Up1
zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZEjAcDUFJERhFAAAA
QQDBkfo7VQs5GnywcoN2J3KV5hxlTwvvL1jc5clioQt9118GAVRl5VB25GYmPuvK7SDS66
s5MT6LxWcyD+iy3GKzAAAAC3Rlc3RSU0ExMDI0AQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH PRIVATE KEY-----
"""

INVALID_PEM_FILE = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAsNGDUqiPU9VRb0bCDno2fX3ois9UoBn23vV6ubRM7dsiQrG8oPsb
XLgrMDYXamOQNWTexutB2y+Px4f05S4RSeMzR1cpc/Zgw8d8qeCCHCtpW+eunX0w9AeREP
SKrm+LcC1HSykAgX8oZiSb7BKisZuCeEFoCPga4fz5t3eKYj8AAAIQB1vNFQdbzRUAAAAH
c3NoLXJzYQAAAIEAsNGDUqiPU9VRb0bCDno2fX3ois9UoBn23vV6ubRM7dsiQrG8oPsbXL
grMDYXamOQNWTexutB2y+Px4f05S4RSeMzR1cpc/Zgw8d8qeCCHCtpW+eunX0w9AeREPSK
rm+LcC1HSykAgX8oZiSb7BKisZuCeEFoCPga4fz5t3eKYj8AAAADAQABAAAAgEgun4+k5C
3zDXWBy0KhvZDpT38rOH7LWq6WQ+1/n1ASfx/+8uQ83mSxgmACFPkHgB1r+k32SEI0Xlu0
MtNERSXYMBZUxUQrCl4RucfiAfoy9Bq69PCm4Dzw4MuCZsYq0R2VbVPJRm5ImV/qJgyFNv
BByzVi+qxRHE1mqP7REbKRAAAAQQC5nX+PTU1FXx+6Ri2ZCi6EjEKMHr7gHcABhMinZYOt
N59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3gi27bAAAAQQDp2G5Nw0qYWn7HWm9Up1
zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZEjAcDUFJERhFAAAA
QQDBkfo7VQs5GnywcoN2J3KV5hxlTwvvL1jc5clioQt9118GAVRl5VB25GYmPuvK7SDS66
s5MT6LxWcyD+iy3GKzAAAAC3Rlc3RSU0ExMDI0AQIDBAUGBwgJCgsMDQ4P
-----END OPENSSH KEY-----
"""

PEM_DECODED = b'openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x97\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x02\x10\x07[\xcd\x15\x07[\xcd\x15\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v\'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00\x0btestRSA1024\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'


def test_unmarshal_openssh_private_key():
    assert pem.unmarshal(PEM_FILE) == [
        pem.PEMBlock(
            header="OPENSSH PRIVATE KEY",
            footer="OPENSSH PRIVATE KEY",
            data=PEM_DECODED,
        ),
    ]


def test_marshal_openssh_private_key():
    got = pem.marshal(
        pem.PEMBlock(
            header="OPENSSH PRIVATE KEY",
            footer="OPENSSH PRIVATE KEY",
            data=PEM_DECODED,
        ),
        width=70,
        use_spaces=False,
    )
    print(got.decode("utf-8"))
    assert got == PEM_FILE


def test_is_pem():
    assert pem.is_pem(PEM_FILE) is True
    assert pem.is_pem(PEM_DECODED) is False


def test_unmarshal_invalid_pem():
    with pytest.raises(ValueError, match="Header and footer do not match: OPENSSH PRIVATE KEY != OPENSSH KEY"):
        pem.unmarshal(INVALID_PEM_FILE)
