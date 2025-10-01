import dataclasses
from typing import Any
from unittest.mock import patch

import pytest

from ssh_key_mgr import openssh, pem
from ssh_key_mgr.openssh import KDFOptions, OpenSSHCheck, OpenSSHPublicKeyEd25519, OpenSSHPublicKeyRSA
from ssh_key_mgr.openssh.aes.base import EncryptedBytes
from ssh_key_mgr.openssh.bcrypt.base import Rounds, Salt

# region RSA_1024 - Plain

RSA_1024_NONE_FILE_PEM = b"""-----BEGIN OPENSSH PRIVATE KEY-----
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

RSA_1024_NONE_FILE_DATA = b'openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x97\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x02\x10\x07[\xcd\x15\x07[\xcd\x15\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v\'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00\x0btestRSA1024\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'

RSA_1024_NONE_BLOCK = pem.PEMBlock(
    header="OPENSSH PRIVATE KEY", footer="OPENSSH PRIVATE KEY", data=RSA_1024_NONE_FILE_DATA
)

RSA_1024_NONE_PRIVATE_KEY_RAW = EncryptedBytes(
    value=b"\x07[\xcd\x15\x07[\xcd\x15\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb\"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00\x0btestRSA1024\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
)

RSA_1024_NONE_PUBLIC_KEY = openssh.OpenSSHPublicKeyRSA(
    e=65537,
    n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
)

RSA_1024_NONE_PRIVATE_KEY = openssh.OpenSSHRSAPrivateKey(
    check=OpenSSHCheck(check_int_1=123456789, check_int_2=123456789),
    n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    e=65537,
    d=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
    iqmp=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
    p=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
    q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
    comment="testRSA1024",
)

RSA_1024_NONE_FILE = openssh.EncryptedPrivateFilePlain(
    public_key=OpenSSHPublicKeyRSA(
        e=65537,
        n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    ),
    encrypted_private_key=EncryptedBytes(
        value=b"\x07[\xcd\x15\x07[\xcd\x15\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb\"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00\x0btestRSA1024\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f"
    ),
)

# endregion

# region RSA_1024 - AES256

RSA_1024_AES256_FILE_PEM = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAwMTIzND
U2Nzg5QUJDREVGAAAAEAAAAAEAAACXAAAAB3NzaC1yc2EAAAADAQABAAAAgQCw0YNSqI9T
1VFvRsIOejZ9feiKz1SgGfbe9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/
TlLhFJ4zNHVylz9mDDx3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKx
m4J4QWgI+Brh/Pm3d4piPwAAAhCrFbzCP+oQrhS1Rp484MMdwozwOJy28eVmfRObopBrgt
eNHQ4rtyTZ4xR8NqqWm47evgOimDvvmFLoj930A6aGgzYjDPlkDx2WFLVCoR8hldFOjNiu
b/LojGUP8uhy+rrmfR2qdCojRu6W5lACGxIJ70Cs3+f0J4voVuYku/kXUqRGgyNkiogWIZ
hIUkdMoTLAzNoT0B123w77EHVnx0rbCeBnfhCfUfg82DISUu3jXg9vcK8PG+0iTi1PWYUu
ZdpWSZ/K135/07/hs7Wos4B44BeN7robM3okn73EVDuQ8L1fyPXaWzyFarbZQoZSvjRUei
OGNKfYK5ilMt3t0iWVZ0foz8Ft6lNZLbOe5Tdj8lAn3ABlOJJ+Of1BkDYzlDc0TdvjU71C
tWrVD9uNr+kzSwhz2SKp8fcCsy3/HHKtBm6hVUKdBNTG0PT/YmAa+j5uVp6slvyzfJkqJf
v1bl+4Y3ATH8MxyAZNVOzGh6BLokN/QCkiijeZg5dLkuNHf+fgqZEDdKZDBCTKPRDmQtU0
1WR0A3DUx0WwjCwy34PIzhzKD+q5pFo3DUO3Ei18hAayPspqTzdRAAKZaldIQVjnVWPsTK
nhL0R2WJQm6bsyKdHsMZpU6GC1Vl7ghqP6JA//aiqcqBGtWWFf7hVJBt0vOgdGXYCdDYGy
CZ2BvAxKbkboqGa7JUg4uS4OoYRPwFE=
-----END OPENSSH PRIVATE KEY-----
"""

RSA_1024_AES256_FILE_DATA = b'openssh-key-v1\x00\x00\x00\x00\naes256-ctr\x00\x00\x00\x06bcrypt\x00\x00\x00\x18\x00\x00\x00\x100123456789ABCDEF\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x00\x97\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?\x00\x00\x02\x10\xab\x15\xbc\xc2?\xea\x10\xae\x14\xb5F\x9e<\xe0\xc3\x1d\xc2\x8c\xf08\x9c\xb6\xf1\xe5f}\x13\x9b\xa2\x90k\x82\xd7\x8d\x1d\x0e+\xb7$\xd9\xe3\x14|6\xaa\x96\x9b\x8e\xde\xbe\x03\xa2\x98;\xef\x98R\xe8\x8f\xdd\xf4\x03\xa6\x86\x836#\x0c\xf9d\x0f\x1d\x96\x14\xb5B\xa1\x1f!\x95\xd1N\x8c\xd8\xaeo\xf2\xe8\x8ce\x0f\xf2\xe8r\xfa\xba\xe6}\x1d\xaat*#F\xee\x96\xe6P\x02\x1b\x12\t\xef@\xac\xdf\xe7\xf4\'\x8b\xe8V\xe6$\xbb\xf9\x17R\xa4F\x83#d\x8a\x88\x16!\x98HRGL\xa12\xc0\xcc\xda\x13\xd0\x1dv\xdf\x0e\xfb\x10ug\xc7J\xdb\t\xe0g~\x10\x9fQ\xf8<\xd82\x12R\xed\xe3^\x0fop\xaf\x0f\x1b\xed"N-OY\x85.e\xdaVI\x9f\xca\xd7~\x7f\xd3\xbf\xe1\xb3\xb5\xa8\xb3\x80x\xe0\x17\x8d\xee\xba\x1b3z$\x9f\xbd\xc4T;\x90\xf0\xbd_\xc8\xf5\xda[<\x85j\xb6\xd9B\x86R\xbe4Tz#\x864\xa7\xd8+\x98\xa52\xdd\xed\xd2%\x95gG\xe8\xcf\xc1m\xeaSY-\xb3\x9e\xe57c\xf2P\'\xdc\x00e8\x92~9\xfdA\x9063\x9474M\xdb\xe3S\xbdB\xb5j\xd5\x0f\xdb\x8d\xaf\xe93K\x08s\xd9"\xa9\xf1\xf7\x02\xb3-\xff\x1cr\xad\x06n\xa1UB\x9d\x04\xd4\xc6\xd0\xf4\xffb`\x1a\xfa>nV\x9e\xac\x96\xfc\xb3|\x99*%\xfb\xf5n_\xb8cp\x13\x1f\xc31\xc8\x06MT\xec\xc6\x87\xa0K\xa2C\x7f@)"\x8a7\x99\x83\x97K\x92\xe3G\x7f\xe7\xe0\xa9\x91\x03t\xa6C\x04$\xca=\x10\xe6B\xd54\xd5dt\x03p\xd4\xc7E\xb0\x8c,2\xdf\x83\xc8\xce\x1c\xca\x0f\xea\xb9\xa4Z7\rC\xb7\x12-|\x84\x06\xb2>\xcajO7Q\x00\x02\x99jWHAX\xe7Uc\xecL\xa9\xe1/DvX\x94&\xe9\xbb2)\xd1\xec1\x9aT\xe8`\xb5V^\xe0\x86\xa3\xfa$\x0f\xffj*\x9c\xa8\x11\xadYa_\xee\x15I\x06\xdd/:\x07F]\x80\x9d\r\x81\xb2\t\x9d\x81\xbc\x0cJnF\xe8\xa8f\xbb%H8\xb9.\x0e\xa1\x84O\xc0Q'

RSA_1024_AES256_BLOCK = pem.PEMBlock(
    header="OPENSSH PRIVATE KEY", footer="OPENSSH PRIVATE KEY", data=RSA_1024_AES256_FILE_DATA
)

RSA_1024_AES256_PRIVATE_KEY_RAW = EncryptedBytes(
    value=b'\xab\x15\xbc\xc2?\xea\x10\xae\x14\xb5F\x9e<\xe0\xc3\x1d\xc2\x8c\xf08\x9c\xb6\xf1\xe5f}\x13\x9b\xa2\x90k\x82\xd7\x8d\x1d\x0e+\xb7$\xd9\xe3\x14|6\xaa\x96\x9b\x8e\xde\xbe\x03\xa2\x98;\xef\x98R\xe8\x8f\xdd\xf4\x03\xa6\x86\x836#\x0c\xf9d\x0f\x1d\x96\x14\xb5B\xa1\x1f!\x95\xd1N\x8c\xd8\xaeo\xf2\xe8\x8ce\x0f\xf2\xe8r\xfa\xba\xe6}\x1d\xaat*#F\xee\x96\xe6P\x02\x1b\x12\t\xef@\xac\xdf\xe7\xf4\'\x8b\xe8V\xe6$\xbb\xf9\x17R\xa4F\x83#d\x8a\x88\x16!\x98HRGL\xa12\xc0\xcc\xda\x13\xd0\x1dv\xdf\x0e\xfb\x10ug\xc7J\xdb\t\xe0g~\x10\x9fQ\xf8<\xd82\x12R\xed\xe3^\x0fop\xaf\x0f\x1b\xed"N-OY\x85.e\xdaVI\x9f\xca\xd7~\x7f\xd3\xbf\xe1\xb3\xb5\xa8\xb3\x80x\xe0\x17\x8d\xee\xba\x1b3z$\x9f\xbd\xc4T;\x90\xf0\xbd_\xc8\xf5\xda[<\x85j\xb6\xd9B\x86R\xbe4Tz#\x864\xa7\xd8+\x98\xa52\xdd\xed\xd2%\x95gG\xe8\xcf\xc1m\xeaSY-\xb3\x9e\xe57c\xf2P\'\xdc\x00e8\x92~9\xfdA\x9063\x9474M\xdb\xe3S\xbdB\xb5j\xd5\x0f\xdb\x8d\xaf\xe93K\x08s\xd9"\xa9\xf1\xf7\x02\xb3-\xff\x1cr\xad\x06n\xa1UB\x9d\x04\xd4\xc6\xd0\xf4\xffb`\x1a\xfa>nV\x9e\xac\x96\xfc\xb3|\x99*%\xfb\xf5n_\xb8cp\x13\x1f\xc31\xc8\x06MT\xec\xc6\x87\xa0K\xa2C\x7f@)"\x8a7\x99\x83\x97K\x92\xe3G\x7f\xe7\xe0\xa9\x91\x03t\xa6C\x04$\xca=\x10\xe6B\xd54\xd5dt\x03p\xd4\xc7E\xb0\x8c,2\xdf\x83\xc8\xce\x1c\xca\x0f\xea\xb9\xa4Z7\rC\xb7\x12-|\x84\x06\xb2>\xcajO7Q\x00\x02\x99jWHAX\xe7Uc\xecL\xa9\xe1/DvX\x94&\xe9\xbb2)\xd1\xec1\x9aT\xe8`\xb5V^\xe0\x86\xa3\xfa$\x0f\xffj*\x9c\xa8\x11\xadYa_\xee\x15I\x06\xdd/:\x07F]\x80\x9d\r\x81\xb2\t\x9d\x81\xbc\x0cJnF\xe8\xa8f\xbb%H8\xb9.\x0e\xa1\x84O\xc0Q'
)

RSA_1024_AES256_PUBLIC_KEY = openssh.OpenSSHPublicKeyRSA(
    e=65537,
    n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
)

RSA_1024_AES256_PRIVATE_KEY = openssh.OpenSSHRSAPrivateKey(
    check=OpenSSHCheck(check_int_1=123456789, check_int_2=123456789),
    n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    e=65537,
    d=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
    iqmp=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
    p=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
    q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
    comment="testRSA1024",
)

RSA_1024_AES256_FILE = openssh.EncryptedPrivateFileAes256(
    kdf_opts=KDFOptions(salt=Salt(value=b"0123456789ABCDEF"), rounds=Rounds(value=16)),
    public_key=OpenSSHPublicKeyRSA(
        e=65537,
        n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    ),
    encrypted_private_key=EncryptedBytes(
        value=b'\xab\x15\xbc\xc2?\xea\x10\xae\x14\xb5F\x9e<\xe0\xc3\x1d\xc2\x8c\xf08\x9c\xb6\xf1\xe5f}\x13\x9b\xa2\x90k\x82\xd7\x8d\x1d\x0e+\xb7$\xd9\xe3\x14|6\xaa\x96\x9b\x8e\xde\xbe\x03\xa2\x98;\xef\x98R\xe8\x8f\xdd\xf4\x03\xa6\x86\x836#\x0c\xf9d\x0f\x1d\x96\x14\xb5B\xa1\x1f!\x95\xd1N\x8c\xd8\xaeo\xf2\xe8\x8ce\x0f\xf2\xe8r\xfa\xba\xe6}\x1d\xaat*#F\xee\x96\xe6P\x02\x1b\x12\t\xef@\xac\xdf\xe7\xf4\'\x8b\xe8V\xe6$\xbb\xf9\x17R\xa4F\x83#d\x8a\x88\x16!\x98HRGL\xa12\xc0\xcc\xda\x13\xd0\x1dv\xdf\x0e\xfb\x10ug\xc7J\xdb\t\xe0g~\x10\x9fQ\xf8<\xd82\x12R\xed\xe3^\x0fop\xaf\x0f\x1b\xed"N-OY\x85.e\xdaVI\x9f\xca\xd7~\x7f\xd3\xbf\xe1\xb3\xb5\xa8\xb3\x80x\xe0\x17\x8d\xee\xba\x1b3z$\x9f\xbd\xc4T;\x90\xf0\xbd_\xc8\xf5\xda[<\x85j\xb6\xd9B\x86R\xbe4Tz#\x864\xa7\xd8+\x98\xa52\xdd\xed\xd2%\x95gG\xe8\xcf\xc1m\xeaSY-\xb3\x9e\xe57c\xf2P\'\xdc\x00e8\x92~9\xfdA\x9063\x9474M\xdb\xe3S\xbdB\xb5j\xd5\x0f\xdb\x8d\xaf\xe93K\x08s\xd9"\xa9\xf1\xf7\x02\xb3-\xff\x1cr\xad\x06n\xa1UB\x9d\x04\xd4\xc6\xd0\xf4\xffb`\x1a\xfa>nV\x9e\xac\x96\xfc\xb3|\x99*%\xfb\xf5n_\xb8cp\x13\x1f\xc31\xc8\x06MT\xec\xc6\x87\xa0K\xa2C\x7f@)"\x8a7\x99\x83\x97K\x92\xe3G\x7f\xe7\xe0\xa9\x91\x03t\xa6C\x04$\xca=\x10\xe6B\xd54\xd5dt\x03p\xd4\xc7E\xb0\x8c,2\xdf\x83\xc8\xce\x1c\xca\x0f\xea\xb9\xa4Z7\rC\xb7\x12-|\x84\x06\xb2>\xcajO7Q\x00\x02\x99jWHAX\xe7Uc\xecL\xa9\xe1/DvX\x94&\xe9\xbb2)\xd1\xec1\x9aT\xe8`\xb5V^\xe0\x86\xa3\xfa$\x0f\xffj*\x9c\xa8\x11\xadYa_\xee\x15I\x06\xdd/:\x07F]\x80\x9d\r\x81\xb2\t\x9d\x81\xbc\x0cJnF\xe8\xa8f\xbb%H8\xb9.\x0e\xa1\x84O\xc0Q'
    ),
)

# endregion

# region ED25519 - Plain

ED25519_NONE_FILE_PEM = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAZv0QJaYTN/oVBusFn3DuWyFCGqjC2tssMXDitcDFm4QAAAJA63mixOt5o
sQAAAAtzc2gtZWQyNTUxOQAAACAZv0QJaYTN/oVBusFn3DuWyFCGqjC2tssMXDitcDFm4Q
AAAEDU7nLb+RNYStW22PH3afitOv58KMvx1Pvgl6iPRHVYQhm/RAlphM3+hUG6wWfcO5bI
UIaqMLa2ywxcOK1wMWbhAAAAC3Rlc3RFRDI1NTE5AQI=
-----END OPENSSH PRIVATE KEY-----
"""

ED25519_NONE_FILE_DATA = b"openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00\x90:\xdeh\xb1:\xdeh\xb1\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00@\xd4\xeer\xdb\xf9\x13XJ\xd5\xb6\xd8\xf1\xf7i\xf8\xad:\xfe|(\xcb\xf1\xd4\xfb\xe0\x97\xa8\x8fDuXB\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00\x0btestED25519\x01\x02"

ED25519_NONE_BLOCK = pem.PEMBlock(
    header="OPENSSH PRIVATE KEY", footer="OPENSSH PRIVATE KEY", data=ED25519_NONE_FILE_DATA
)

ED25519_NONE_PRIVATE_KEY_RAW = EncryptedBytes(
    value=b":\xdeh\xb1:\xdeh\xb1\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00@\xd4\xeer\xdb\xf9\x13XJ\xd5\xb6\xd8\xf1\xf7i\xf8\xad:\xfe|(\xcb\xf1\xd4\xfb\xe0\x97\xa8\x8fDuXB\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00\x0btestED25519\x01\x02"
)

ED25519_NONE_PUBLIC_KEY = openssh.OpenSSHPublicKeyEd25519(
    value=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1"
)

ED25519_NONE_PRIVATE_KEY = openssh.OpenSSHEd25519PrivateKey(
    check=OpenSSHCheck(check_int_1=987654321, check_int_2=987654321),
    public=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1",
    private=b"\xd4\xeer\xdb\xf9\x13XJ\xd5\xb6\xd8\xf1\xf7i\xf8\xad:\xfe|(\xcb\xf1\xd4\xfb\xe0\x97\xa8\x8fDuXB\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1",
    comment="testED25519",
)

ED25519_NONE_FILE = openssh.EncryptedPrivateFilePlain(
    public_key=OpenSSHPublicKeyEd25519(
        value=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1"
    ),
    encrypted_private_key=EncryptedBytes(
        value=b":\xdeh\xb1:\xdeh\xb1\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00@\xd4\xeer\xdb\xf9\x13XJ\xd5\xb6\xd8\xf1\xf7i\xf8\xad:\xfe|(\xcb\xf1\xd4\xfb\xe0\x97\xa8\x8fDuXB\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00\x0btestED25519\x01\x02"
    ),
)

# endregion

# region ED25519 - AES256

ED25519_AES256_FILE_PEM = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAwMTIzND
U2Nzg5QUJDREVGAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBm/RAlphM3+hUG6
wWfcO5bIUIaqMLa2ywxcOK1wMWbhAAAAkJaQGWYCb7UKFLVGkjzgwx3Vm6MNqYdJ5dassN
C1WzE+Ai+lSWR308NCx2AxrrAoSLb9shdwT68zQczfYVT4/Q7Vb8jD/VYmWBWomnMjpleA
oPUj57qVGEH4/sfhtFlOw5r+aGoQZcHoxnfAmUNdtDW4VxYb2+yDDMRDDB+jn3ctjCCszO
3rXuL+KAUmHn1YKg==
-----END OPENSSH PRIVATE KEY-----
"""

ED25519_AES256_FILE_DATA = b"openssh-key-v1\x00\x00\x00\x00\naes256-ctr\x00\x00\x00\x06bcrypt\x00\x00\x00\x18\x00\x00\x00\x100123456789ABCDEF\x00\x00\x00\x10\x00\x00\x00\x01\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1\x00\x00\x00\x90\x96\x90\x19f\x02o\xb5\n\x14\xb5F\x92<\xe0\xc3\x1d\xd5\x9b\xa3\r\xa9\x87I\xe5\xd6\xac\xb0\xd0\xb5[1>\x02/\xa5Idw\xd3\xc3B\xc7`1\xae\xb0(H\xb6\xfd\xb2\x17pO\xaf3A\xcc\xdfaT\xf8\xfd\x0e\xd5o\xc8\xc3\xfdV&X\x15\xa8\x9as#\xa6W\x80\xa0\xf5#\xe7\xba\x95\x18A\xf8\xfe\xc7\xe1\xb4YN\xc3\x9a\xfehj\x10e\xc1\xe8\xc6w\xc0\x99C]\xb45\xb8W\x16\x1b\xdb\xec\x83\x0c\xc4C\x0c\x1f\xa3\x9fw-\x8c \xac\xcc\xed\xeb^\xe2\xfe(\x05&\x1e}X*"

ED25519_AES256_BLOCK = pem.PEMBlock(
    header="OPENSSH PRIVATE KEY", footer="OPENSSH PRIVATE KEY", data=ED25519_AES256_FILE_DATA
)

ED25519_AES256_PRIVATE_KEY_RAW = EncryptedBytes(
    value=b"\x96\x90\x19f\x02o\xb5\n\x14\xb5F\x92<\xe0\xc3\x1d\xd5\x9b\xa3\r\xa9\x87I\xe5\xd6\xac\xb0\xd0\xb5[1>\x02/\xa5Idw\xd3\xc3B\xc7`1\xae\xb0(H\xb6\xfd\xb2\x17pO\xaf3A\xcc\xdfaT\xf8\xfd\x0e\xd5o\xc8\xc3\xfdV&X\x15\xa8\x9as#\xa6W\x80\xa0\xf5#\xe7\xba\x95\x18A\xf8\xfe\xc7\xe1\xb4YN\xc3\x9a\xfehj\x10e\xc1\xe8\xc6w\xc0\x99C]\xb45\xb8W\x16\x1b\xdb\xec\x83\x0c\xc4C\x0c\x1f\xa3\x9fw-\x8c \xac\xcc\xed\xeb^\xe2\xfe(\x05&\x1e}X*"
)

ED25519_AES256_PUBLIC_KEY = openssh.OpenSSHPublicKeyEd25519(
    value=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1"
)

ED25519_AES256_PRIVATE_KEY = openssh.OpenSSHEd25519PrivateKey(
    check=OpenSSHCheck(check_int_1=987654321, check_int_2=987654321),
    public=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1",
    private=b"\xd4\xeer\xdb\xf9\x13XJ\xd5\xb6\xd8\xf1\xf7i\xf8\xad:\xfe|(\xcb\xf1\xd4\xfb\xe0\x97\xa8\x8fDuXB\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1",
    comment="testED25519",
)

ED25519_AES256_FILE = openssh.EncryptedPrivateFileAes256(
    kdf_opts=KDFOptions(salt=Salt(value=b"0123456789ABCDEF"), rounds=Rounds(value=16)),
    public_key=OpenSSHPublicKeyEd25519(
        value=b"\x19\xbfD\ti\x84\xcd\xfe\x85A\xba\xc1g\xdc;\x96\xc8P\x86\xaa0\xb6\xb6\xcb\x0c\\8\xadp1f\xe1"
    ),
    encrypted_private_key=EncryptedBytes(
        value=b"\x96\x90\x19f\x02o\xb5\n\x14\xb5F\x92<\xe0\xc3\x1d\xd5\x9b\xa3\r\xa9\x87I\xe5\xd6\xac\xb0\xd0\xb5[1>\x02/\xa5Idw\xd3\xc3B\xc7`1\xae\xb0(H\xb6\xfd\xb2\x17pO\xaf3A\xcc\xdfaT\xf8\xfd\x0e\xd5o\xc8\xc3\xfdV&X\x15\xa8\x9as#\xa6W\x80\xa0\xf5#\xe7\xba\x95\x18A\xf8\xfe\xc7\xe1\xb4YN\xc3\x9a\xfehj\x10e\xc1\xe8\xc6w\xc0\x99C]\xb45\xb8W\x16\x1b\xdb\xec\x83\x0c\xc4C\x0c\x1f\xa3\x9fw-\x8c \xac\xcc\xed\xeb^\xe2\xfe(\x05&\x1e}X*"
    ),
)

# endregion

PASSPHRASE_ENC = openssh.SecretBytes(b"correct horse battery staple")
PASSPHRASE_NONE = None
PASSPHRASE_NONE_ALT = openssh.SecretBytes(b"")
KDF_OPTS = openssh.KDFOptions(
    salt=Salt(b"0123456789ABCDEF"),
    rounds=Rounds(16),
)


@dataclasses.dataclass
class TCase:
    name: str


def nameid(val: Any):
    if isinstance(val, TCase):
        return val.name


@dataclasses.dataclass
class DecodeDataCase(TCase):
    data: bytes
    want: openssh.EncryptedPrivateFile


decode_data_cases = [
    DecodeDataCase("RSA-None", RSA_1024_NONE_FILE_DATA, RSA_1024_NONE_FILE),
    DecodeDataCase("RSA-Enc", RSA_1024_AES256_FILE_DATA, RSA_1024_AES256_FILE),
    DecodeDataCase("Ed25519-None", ED25519_NONE_FILE_DATA, ED25519_NONE_FILE),
    DecodeDataCase("Ed25519-Enc", ED25519_AES256_FILE_DATA, ED25519_AES256_FILE),
]


@pytest.mark.parametrize("case", decode_data_cases, ids=nameid)
def test_decode_data(case: DecodeDataCase):
    got = openssh.decode_data(case.data)
    assert got == case.want


@dataclasses.dataclass
class EncodeDataCase(TCase):
    data: openssh.EncryptedPrivateFile
    want: bytes


encode_data_cases = [
    EncodeDataCase("RSA-None", RSA_1024_NONE_FILE, RSA_1024_NONE_FILE_DATA),
    EncodeDataCase("RSA-Enc", RSA_1024_AES256_FILE, RSA_1024_AES256_FILE_DATA),
    EncodeDataCase("Ed25519-None", ED25519_NONE_FILE, ED25519_NONE_FILE_DATA),
]


@pytest.mark.parametrize("case", encode_data_cases, ids=nameid)
def test_encode_data(case: EncodeDataCase):
    got = openssh.encode_data(case.data)
    assert got == case.want


@dataclasses.dataclass
class DecodeFileCase(TCase):
    data: bytes
    want: openssh.EncryptedPrivateFile


decode_file_cases = [
    DecodeFileCase("RSA-None", RSA_1024_NONE_FILE_PEM, RSA_1024_NONE_FILE),
    DecodeFileCase("RSA-Enc", RSA_1024_AES256_FILE_PEM, RSA_1024_AES256_FILE),
    DecodeFileCase("Ed25519-None", ED25519_NONE_FILE_PEM, ED25519_NONE_FILE),
    DecodeFileCase("Ed25519-Enc", ED25519_AES256_FILE_PEM, ED25519_AES256_FILE),
]


@pytest.mark.parametrize("case", decode_file_cases, ids=nameid)
def test_decode_file(case: DecodeFileCase):
    got = openssh.decode_file(case.data)
    assert got == case.want


@dataclasses.dataclass
class EncodeFileCase(TCase):
    data: openssh.EncryptedPrivateFile
    want: bytes


encode_file_cases = [
    EncodeFileCase("RSA-None", RSA_1024_NONE_FILE, RSA_1024_NONE_FILE_PEM),
    EncodeFileCase("RSA-Enc", RSA_1024_AES256_FILE, RSA_1024_AES256_FILE_PEM),
    EncodeFileCase("Ed25519-None", ED25519_NONE_FILE, ED25519_NONE_FILE_PEM),
    EncodeFileCase("Ed25519-Enc", ED25519_AES256_FILE, ED25519_AES256_FILE_PEM),
]


@pytest.mark.parametrize("case", encode_file_cases, ids=nameid)
def test_encode_file(case: EncodeFileCase):
    got = openssh.encode_file(case.data)
    assert got == case.want


@dataclasses.dataclass
class UnmarshalKeyCase(TCase):
    data: bytes
    passphrase: openssh.SecretBytes | None
    want: openssh.OpenSSHPrivateKey


unmarshal_key_cases = [
    UnmarshalKeyCase("RSA-None", RSA_1024_NONE_FILE_DATA, PASSPHRASE_NONE, RSA_1024_NONE_PRIVATE_KEY),
    UnmarshalKeyCase("RSA-None-Alt", RSA_1024_NONE_FILE_DATA, PASSPHRASE_NONE_ALT, RSA_1024_NONE_PRIVATE_KEY),
    UnmarshalKeyCase("RSA-Enc", RSA_1024_AES256_FILE_DATA, PASSPHRASE_ENC, RSA_1024_AES256_PRIVATE_KEY),
    UnmarshalKeyCase("ED25519-Enc", ED25519_AES256_FILE_DATA, PASSPHRASE_ENC, ED25519_AES256_PRIVATE_KEY),
    UnmarshalKeyCase("ED25519-None", ED25519_NONE_FILE_DATA, PASSPHRASE_NONE, ED25519_NONE_PRIVATE_KEY),
    UnmarshalKeyCase("ED25519-None-Alt", ED25519_NONE_FILE_DATA, PASSPHRASE_NONE_ALT, ED25519_NONE_PRIVATE_KEY),
]


@pytest.mark.parametrize("case", unmarshal_key_cases, ids=nameid)
def test_unmarshal_key(case: UnmarshalKeyCase):
    file = openssh.decode_data(case.data)
    got = file.private_key(case.passphrase)
    assert got == case.want


def test_unmarshal_key_raises_encrypted() -> None:
    file = openssh.decode_data(RSA_1024_AES256_FILE_DATA)
    with pytest.raises(ValueError, match="Passphrase is required for encrypted private key"):
        file.private_key(None)


def test_unmarshal_key_raises_none() -> None:
    file = openssh.decode_data(RSA_1024_NONE_FILE_DATA)
    with pytest.raises(ValueError, match="Passphrase should not be provided for unencrypted private key"):
        file.private_key(openssh.SecretBytes(b"non-empty"))


@dataclasses.dataclass
class MarshalKeyEncCase(TCase):
    data: openssh.OpenSSHPrivateKey
    passphrase: openssh.SecretBytes
    args: openssh.EncryptedPrivateFileAes256
    want: EncryptedBytes


marshal_key_enc_cases = [
    MarshalKeyEncCase(
        "RSA", RSA_1024_AES256_PRIVATE_KEY, PASSPHRASE_ENC, RSA_1024_AES256_FILE, RSA_1024_AES256_PRIVATE_KEY_RAW
    ),
    MarshalKeyEncCase(
        "Ed25519", ED25519_AES256_PRIVATE_KEY, PASSPHRASE_ENC, ED25519_AES256_FILE, ED25519_AES256_PRIVATE_KEY_RAW
    ),
]


@pytest.mark.parametrize("case", marshal_key_enc_cases, ids=nameid)
def test_marshal_key_encrypted_case(case: MarshalKeyEncCase):
    want = case.want
    got = openssh.enc.encrypt_aes256_ctr_bcrypt(
        case.data, case.passphrase, case.args.kdf_opts.rounds, case.args.kdf_opts.salt
    )
    assert got == want


def test_encode_key_encrypted():
    want = ED25519_AES256_FILE_DATA
    file = openssh.EncryptedPrivateFileAes256(
        public_key=ED25519_AES256_PUBLIC_KEY,
        kdf_opts=KDF_OPTS,
        encrypted_private_key=openssh.enc.encrypt_aes256_ctr_bcrypt(
            ED25519_AES256_PRIVATE_KEY,
            PASSPHRASE_ENC,
            KDF_OPTS.rounds,
            KDF_OPTS.salt,
        ),
    )
    got = openssh.encode_data(file)
    assert got == want


def test_encode_key_plain():
    want = ED25519_NONE_FILE_DATA
    file = openssh.EncryptedPrivateFilePlain(
        public_key=ED25519_NONE_PUBLIC_KEY,
        encrypted_private_key=openssh.enc.encrypt_plain(ED25519_NONE_PRIVATE_KEY),
    )
    got = openssh.encode_data(file)
    assert got == want


# region CanParse


@dataclasses.dataclass
class CanParseDataCase(TCase):
    data: bytes
    want: bool


can_parse_data_cases = [
    CanParseDataCase("RSA-NoneData", RSA_1024_NONE_FILE_DATA, True),
    CanParseDataCase("RSA-EncData", RSA_1024_AES256_FILE_DATA, True),
    CanParseDataCase("Ed25519-NoneData", ED25519_NONE_FILE_DATA, True),
    CanParseDataCase("Ed25519-EncData", ED25519_AES256_FILE_DATA, True),
    CanParseDataCase("Invalid", b"invalid", False),
]


@pytest.mark.parametrize("case", can_parse_data_cases, ids=nameid)
def test_can_parse_data(case: CanParseDataCase):
    assert openssh.can_parse_data(case.data) is case.want


@dataclasses.dataclass
class CanParseFileCase(TCase):
    data: bytes
    want: bool


can_parse_file_cases = [
    CanParseFileCase("RSA-NoneData", RSA_1024_NONE_FILE_PEM, True),
    CanParseFileCase("RSA-EncData", RSA_1024_AES256_FILE_PEM, True),
    CanParseFileCase("Ed25519-NoneData", ED25519_NONE_FILE_PEM, True),
    CanParseFileCase("Ed25519-EncData", ED25519_AES256_FILE_PEM, True),
    CanParseFileCase("Invalid", b"invalid", False),
]


@pytest.mark.parametrize("case", can_parse_file_cases, ids=nameid)
def test_can_parse_file(case: CanParseFileCase):
    assert openssh.can_parse_file(case.data) is case.want


@dataclasses.dataclass
class CanParseBlockCase(TCase):
    data: pem.PEMBlock
    want: bool


can_parse_block_cases = [
    CanParseBlockCase("RSA-NoneData", RSA_1024_NONE_BLOCK, True),
    CanParseBlockCase("RSA-EncData", RSA_1024_AES256_BLOCK, True),
    CanParseBlockCase("Ed25519-NoneData", ED25519_NONE_BLOCK, True),
    CanParseBlockCase("Ed25519-EncData", ED25519_AES256_BLOCK, True),
    CanParseBlockCase("Invalid", pem.PEMBlock(header="invalid", footer="invalid", data=b"invalid"), False),
]


@pytest.mark.parametrize("case", can_parse_block_cases, ids=nameid)
def test_can_parse_block(case: CanParseBlockCase):
    assert openssh.can_parse_pem(case.data) is case.want


# endregion


def test_create_check() -> None:
    with patch("os.urandom") as mock_urandom:
        mock_urandom.return_value = b"\x89\xab\xcd\xef"
        check = openssh.OpenSSHCheck.create(None)
        mock_urandom.assert_called_once_with(4)
    assert check.check_int_1 == 2309737967
    assert check.check_int_2 == 2309737967


def test_check_validate() -> None:
    with pytest.raises(ValueError, match="Check integers do not match"):
        openssh.OpenSSHCheck(check_int_1=1, check_int_2=2)


def test_encrypted_private_file_abstract() -> None:
    with pytest.raises(NotImplementedError):
        openssh.EncryptedPrivateFile().private_key(None)


def test_decode_pem_raises() -> None:
    block = pem.PEMBlock(header="invalid", footer="invalid", data=b"invalid")
    with pytest.raises(ValueError, match="Invalid PEM header/footer, expected OPENSSH PRIVATE KEY"):
        openssh.decode_pem(block)


def test_decode_file_raises() -> None:
    blocks = RSA_1024_AES256_FILE_PEM + b"\n" + ED25519_AES256_FILE_PEM
    with pytest.raises(ValueError, match="Expected exactly one PEM block"):
        openssh.decode_file(blocks)


def test_ed25519_validate_private_key():
    with pytest.raises(ValueError, match="Invalid public key length"):
        openssh.OpenSSHEd25519PrivateKey(
            check=OpenSSHCheck(check_int_1=1, check_int_2=1),
            public=b"short",
            private=b"\x00" * 64,
            comment="test",
        )
    with pytest.raises(ValueError, match="Invalid private key length"):
        openssh.OpenSSHEd25519PrivateKey(
            check=OpenSSHCheck(check_int_1=1, check_int_2=1),
            public=b"\x00" * 32,
            private=b"short",
            comment="test",
        )
    with pytest.raises(ValueError, match="Private key does not end with public key"):
        openssh.OpenSSHEd25519PrivateKey(
            check=OpenSSHCheck(check_int_1=1, check_int_2=1),
            public=b"\x01" * 32,
            private=b"\x00" * 64,
            comment="test",
        )


def test_padding():
    from ssh_proto_types import StreamReader

    stream = StreamReader(b"\x01\x02\x03\x04\x05\x06\x07\x08")
    stream.read_raw(1)

    with pytest.raises(ValueError, match="Invalid padding"):
        openssh.enc.verify_padding(stream, 8)
