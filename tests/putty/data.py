from typing import Literal, TypedDict

from ssh_key_mgr.putty import (
    EncryptedBytes,
    Encryption_AES256_CBC,
    Encryption_AES256_CBC_Params,
    Encryption_NONE,
    Encryption_NONE_Params,
    PuttyFileV3,
    PuttyKeyEd448,
    PuttyKeyEd25519,
    PuttyKeyRSA,
    PuttyPrivateKeyEd448,
    PuttyPrivateKeyEd25519,
    PuttyPrivateKeyRSA,
    PuttyPublicKeyEd448,
    PuttyPublicKeyEd25519,
    PuttyPublicKeyRSA,
)
from ssh_key_mgr.putty.checksum import Mac, MacKey
from ssh_key_mgr.putty.encryption.aes.base import IV, CipherKey
from ssh_key_mgr.putty.encryption.argon.base import Argon2Params, ArgonID, MemoryCost, Parallelism, Salt, TimeCost
from ssh_key_mgr.secretstr import SecretBytes

PASSPHRASE_ENC = SecretBytes(b"correct horse battery staple")
PASSPHRASE_NONE = None
PASSPHRASE_NONE_ALT = SecretBytes(b"")


class AesTestVectorT(TypedDict):
    CipherKey: CipherKey
    IV: IV
    Decrypted: bytes
    Encrypted: EncryptedBytes


PUTTY_AES: dict[str, AesTestVectorT] = {
    "TestVector_1": {
        "CipherKey": CipherKey(
            b"6$\xb6S\xc1&N\x7f\x19-\xf8jt8\xd5\x19\x1c\xc4\xc9\xda\xc9\x8c\xa8\xddt\xc2\xda\x8b\x9e\xcf\xe5\x15"
        ),
        "IV": IV(b"\xef\xb5\x83\xd3v\xb1\x9d\x92\xd8\x1eu\xbe\xa35v\x8d"),
        "Decrypted": b"decrypted_1\x01\x02\x03\x04\x05",
        "Encrypted": EncryptedBytes(value=b"D\x138X\x8b\x8f\xb8,\xef\x18\x848/i\x02\xe4"),
    },
    "TestVector_2": {
        "CipherKey": CipherKey(
            b'\x88\xccP\xd8\x01\x9dl\xda\xd3\xd0\xe1F\xad\xd1\x13"J\x0bh=W>\xaa\x9bY\xb0\x9a:\xa3\xa1\xcd\xf8'
        ),
        "IV": IV(b"\xfc,\x0c\x13\x9d[q\xc4Z3\x9f\x91\xa8\x19a\x90"),
        "Decrypted": b"decrypted_2\x01\x02\x03\x04\x05",
        "Encrypted": EncryptedBytes(value=b"\xd4\xfd)\x96\xe63\x99o\xca\xaax\xd0_\x18Bf"),
    },
}


class PUTTY_ARGON_DICT(TypedDict):
    Params: Argon2Params
    Passphrase: SecretBytes
    Hash: bytes


PUTTY_ARGON: dict[str, PUTTY_ARGON_DICT] = {
    "TestVector_16": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
        ),
        "Passphrase": SecretBytes(b"passphrase_0"),
        "Hash": b"j|e\xd3\xb6\xc6\x9bD\x9f\xd0\xdd\x1c\x1f\xe5\xff5",
    },
    "TestVector_24": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
        ),
        "Passphrase": SecretBytes(b"passphrase_1"),
        "Hash": b"\xe1\xfd\x81\x1a!R\x10\xe3q\x88Fa&\xf3g\x02\x83\x1c\xcd\x96\t\x87\xa3\x90",
    },
    "TestVector_32": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
        ),
        "Passphrase": SecretBytes(b"passphrase_2"),
        "Hash": b"\xca\x9bx\xc8\xf0\x94L\x8d\xb3\xc0[\x9b\x95\xbd\xd3\xb8\xfb\x19\xa5\xdf\xb6\xaa\nL\x8d9f\xf8\xa3\x8e\x80\xee",
    },
}

SSH_ED25519: Literal["ssh_ed25519"] = "ssh_ed25519"
SSH_RSA_1024: Literal["ssh_rsa_1024"] = "ssh_rsa_1024"
SSH_ED448: Literal["ssh_ed448"] = "ssh_ed448"

KEY_NAMES = (SSH_ED25519, SSH_RSA_1024, SSH_ED448)
KEY_NAMES_T = Literal["ssh_ed25519", "ssh_rsa_1024", "ssh_ed448"]

PUBLIC_KEY_WIRES = {
    SSH_ED25519: b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a",
    SSH_RSA_1024: b'\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?',
    SSH_ED448: b"\x00\x00\x00\tssh-ed448\x00\x00\x009_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80",
}

PRIVATE_KEY_WIRES = {
    SSH_ED25519: b"\x00\x00\x00 \x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`",
    SSH_RSA_1024: b"\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb",
    SSH_ED448: b"\x00\x00\x009l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9[",
}

# region Putty

ENC_AES256_CBC: Literal["aes256_cbc"] = "aes256_cbc"
ENC_NONE: Literal["none"] = "none"

PUTTY_ENC_NAMES = (ENC_AES256_CBC, ENC_NONE)
PUTTY_ENC_NAMES_T = Literal["aes256_cbc", "none"]

PASSPHRASE = {
    ENC_AES256_CBC: SecretBytes(b"correct horse battery staple"),
    ENC_NONE: None,
}

INVALID_PASSPHRASE = {
    ENC_AES256_CBC: None,
    ENC_NONE: SecretBytes(b"invalid"),
}

INCORRECT_PASSPHRASE = {
    ENC_AES256_CBC: SecretBytes(b"Tr0ub4dor&3"),
    ENC_NONE: SecretBytes(b"wrong"),
}

PASSPHRASES = {
    SSH_ED25519: {
        ENC_NONE: None,
        ENC_AES256_CBC: SecretBytes(b"test1"),
    },
    SSH_RSA_1024: {
        ENC_NONE: None,
        ENC_AES256_CBC: SecretBytes(b"test2"),
    },
    SSH_ED448: {
        ENC_NONE: None,
        ENC_AES256_CBC: SecretBytes(b"test3"),
    },
}


class PUTTY_PUBLIC_KEYS_DICT(TypedDict):
    ssh_ed25519: PuttyPublicKeyEd25519
    ssh_rsa_1024: PuttyPublicKeyRSA
    ssh_ed448: PuttyPublicKeyEd448


PUTTY_PUBLIC_KEYS: PUTTY_PUBLIC_KEYS_DICT = {
    SSH_ED25519: PuttyPublicKeyEd25519(
        key=b"\xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a",
    ),
    SSH_RSA_1024: PuttyPublicKeyRSA(
        E=65537,
        N=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    ),
    SSH_ED448: PuttyPublicKeyEd448(
        key=b"_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80",
    ),
}


class PUTTY_PRIVATE_KEYS_DICT(TypedDict):
    ssh_ed25519: PuttyPrivateKeyEd25519
    ssh_rsa_1024: PuttyPrivateKeyRSA
    ssh_ed448: PuttyPrivateKeyEd448


PUTTY_PRIVATE_KEYS: PUTTY_PRIVATE_KEYS_DICT = {
    SSH_ED25519: PuttyPrivateKeyEd25519(
        key=b"\x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`",
    ),
    SSH_RSA_1024: PuttyPrivateKeyRSA(
        D=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
        P=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
        Q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
        Iqmp=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
    ),
    SSH_ED448: PuttyPrivateKeyEd448(
        key=b"l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9[",
    ),
}

PUTTY_KEY = {
    SSH_ED25519: PuttyKeyEd25519(
        public=PuttyPublicKeyEd25519(
            key=b"\xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a",
        ),
        private=PuttyPrivateKeyEd25519(
            key=b"\x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`",
        ),
        comment="RFC8032 7.1 Test Vector 1",
    ),
    SSH_RSA_1024: PuttyKeyRSA(
        public=PuttyPublicKeyRSA(
            E=65537,
            N=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
        ),
        private=PuttyPrivateKeyRSA(
            D=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
            P=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
            Q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
            Iqmp=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
        ),
        comment="testRSA1024",
    ),
    SSH_ED448: PuttyKeyEd448(
        public=PuttyPublicKeyEd448(
            key=b"_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80",
        ),
        private=PuttyPrivateKeyEd448(
            key=b"l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9[",
        ),
        comment="RFC8032 7.4 Test Vector 1",
    ),
}


PUTTY_ENCRYPTED = {
    ENC_AES256_CBC: {
        SSH_ED25519: EncryptedBytes(
            value=b"\xdcI\x85e\xdb)\xe6Q\xf7o\x938h\x7f\xa4\xc3\x8d|\xc9\x82\xc8\xdf\x8eh\xb0}\xa0\x83\xd8\x92\xde\xf6-\xdcD\xd7\t\xbb\xd8K\xf5}9\xa1\x98\x99\xce\xcc"
        ),
        SSH_RSA_1024: EncryptedBytes(
            value=b"M\x8e\xec!\x0f\x14\xbfO\xb6\xad\xf1'T\xdf\xc30\x83\xba\xaf0\xe5\xd5K\x1c\x80\xd66\xe9\x12B\xef\xce\xd4\xcdhe\xdd\x9d\\}\xaa\xca\x9cr\x90_|\x10n\xcf\xbdb\xb3\x01V\x86\x08\x15_\x94)\x88\x01\xf0lOu\x1d\xb2\x9dq<\x80\xa5 \rX\xe4\x81\xa6q}\xbc\x14\xb9[Z\xd6\x14\x1d.I\xfc\x9b\xfc\x9b\xeaM\xc9\xf0G\xdc\xe0\x91F\xb2\xb4\xe4\xbdS\xc6j\r-<\xc3\xbc\x97\xc1\xbd\xf9 \xe0\x0197\xb7=V\xbdQ\xe8\xf0\x94\xef\xb3h\x86\x86xL\x97\xe6?\xf4+\x18\x96_\x7f\xbe\x9d\x94j\x1c\x9c\xb9\x97\x01\xbb\xf1k\xf6\xdd\x8dQZ\xab\xc93\xab\x96|\x13'1\x10m\xe2\xda<{>\xf5~\xfa\x94l\xe0{O\xd1\xe0\xb1\xdc \x11\xb5~\xde\x14\xc1\xfb\x1c|\xa3A-)\xdcN#\xb0\x1eq\xd4\xf7\xa1\xd8:/\xb5\xf2\xe0\x06\xc2#p\"i\xf2\xf5\xe0\xf6\xf2\xc0\xed \x15\"<\xcf\x10-\x91\x8dmj\x14\x89\xb9\x04\x0bO\xac\x95\xbf\xed\x96\x14\x9eT?\xcfL\x03\xf40\xa0v\xac(\xe3\xecJ\x9c\x98h\xcbB\xbb\x8a-\xcf\xb5\xd5o\xeeQ\x80\xa1\x8c\xf2\x13\xad\xcfs_\xf7f;\x86\xd6\xb8\xb9\xc50\xfaG\xa4\n%\xeb\xe7|t\x0b\xd9\xbb\x8d\xfa>\x8b\x84y\x82\xf67t\x82\xb4iU\xf74\xa0\xca\xfc\xf02j\xb1\xc7\xd6\xcbG\xc4\xbf\x11>U\xfd"
        ),
        SSH_ED448: EncryptedBytes(
            value=b'\xef\x1aOK\xb8\xea"#\xbf!\xa4\x03\x14e\x98\x8dqZ\x1d/\xe0\xcd\xcb\xe4g"%\x12\xa9\xc8]\x13\x8f\xf5\xf9rl\x81\xd2\xe7vV\x85>D\xfbp\x06\xee\xd8\xeb\t\x19bnm\xc5?\xe5\xd5Iax\x84'
        ),
    },
    ENC_NONE: {
        SSH_ED25519: EncryptedBytes(
            value=b"\x00\x00\x00 \x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`"
        ),
        SSH_RSA_1024: EncryptedBytes(
            value=b"\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb"
        ),
        SSH_ED448: EncryptedBytes(
            value=b"\x00\x00\x009l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9["
        ),
    },
}

PUTTY_DECRYPTED = {
    ENC_AES256_CBC: {
        SSH_ED25519: b"\x00\x00\x00 \x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c",
        SSH_RSA_1024: b"\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r",
        SSH_ED448: b"\x00\x00\x009l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9[\x01\x02\x03",
    },
    ENC_NONE: {
        SSH_ED25519: b"\x00\x00\x00 \x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`",
        SSH_RSA_1024: b"\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb",
        SSH_ED448: b"\x00\x00\x009l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9[",
    },
}

PUTTY_MAC_KEY = {
    ENC_AES256_CBC: {
        SSH_ED25519: MacKey(
            b':\x009\x08\xa4L\xe0\xa9O;\x8b\xa6-O\x9b\xd2\x0e\xe6\xdaM\xd4\x0ctX\x1f\xde\x1e"\xa3\xe27\xe6'
        ),
        SSH_RSA_1024: MacKey(
            b"\x8ez\xe5\x1f\x9c\xa4\xf8\xbb\x08\xcfro\xfc\x8e\x14\xf8u]\xd3\x9a\xdd\xd8\xd3\x1eJ\xb1\xbe\x93\xfc\xba\x9a\xc1"
        ),
        SSH_ED448: MacKey(
            b"h}\x92A\xab;(&a\x10\xa5\xe9\xde\x11\xf7\x92\x9d\x88\xa4 *k\x93\xa2=\xd7\x80\x8e\x17\x9d\xccE"
        ),
    },
    ENC_NONE: {
        SSH_ED25519: MacKey(b""),
        SSH_RSA_1024: MacKey(b""),
        SSH_ED448: MacKey(b""),
    },
}

PUTTY_MAC = {
    ENC_AES256_CBC: {
        SSH_ED25519: Mac(
            private_mac=b"}h\xef\xb8\xce\x10\xc7xz\xd4\xdc\x97=\xab\xb5#;!\xd2\x06\x92\xbe\xfb'\x8fn\xe8\x9e>\x13N\xef"
        ),
        SSH_RSA_1024: Mac(
            private_mac=b"\xe17<\xd5\r\xec\xfcoY\x170\xbbB\xcf\xae\xd1\xe6\x91\xd2C\xc4\x02eE)|\x89\x0e4\x94'\x14"
        ),
        SSH_ED448: Mac(
            private_mac=b"\xad\xf1?\x15\xb4\xf9\x8fV}N\xd9\xbd9\x88\x10\xb4GN\x01\xf2\x82h\xe7z\xd2\xefZcP\x90{\xec"
        ),
    },
    ENC_NONE: {
        SSH_ED25519: Mac(
            private_mac=b'"\xcf\x83\x08\xed\x9b\xbfDv\x0b\xe8\xd3\xfa9\x1c\xf2\x03\x9f\x06\x9b0\x14Nl\x8db\xc4X\x10\xc1ij'
        ),
        SSH_RSA_1024: Mac(
            private_mac=b"\x8b\x0c6\xad\xd1\x82c\xe2\x13\x1e\x94O\xc4\xa7\xe1MW\x9e\xae\xbd\x96IW\x7f|\xb1\x85\xc5\xf5Wc\xe5"
        ),
        SSH_ED448: Mac(
            private_mac=b"H\xc2\x1e\xa5\x17\x15\n7\x97 \x96\x89\x0e/7\xb7\xde|2h\x931`t \xb8\x02V\x831\xfe\x1c"
        ),
    },
}


class PUTTY_DECRYPTION_PARAMS_DICT(TypedDict):
    aes256_cbc: dict[KEY_NAMES_T, Encryption_AES256_CBC_Params]
    none: dict[KEY_NAMES_T, Encryption_NONE_Params]


PUTTY_DECRYPTION_PARAMS: PUTTY_DECRYPTION_PARAMS_DICT = {
    ENC_AES256_CBC: {
        SSH_ED25519: Encryption_AES256_CBC_Params(
            argon2_params=Argon2Params(
                type=ArgonID.ID,
                memory_cost=MemoryCost(8192),
                time_cost=TimeCost(21),
                parallelism=Parallelism(1),
                salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
            ),
        ),
        SSH_RSA_1024: Encryption_AES256_CBC_Params(
            argon2_params=Argon2Params(
                type=ArgonID.ID,
                memory_cost=MemoryCost(8192),
                time_cost=TimeCost(21),
                parallelism=Parallelism(1),
                salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
            ),
        ),
        SSH_ED448: Encryption_AES256_CBC_Params(
            argon2_params=Argon2Params(
                type=ArgonID.ID,
                memory_cost=MemoryCost(8192),
                time_cost=TimeCost(21),
                parallelism=Parallelism(1),
                salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
            ),
        ),
    },
    ENC_NONE: {
        SSH_ED25519: Encryption_NONE_Params(),
        SSH_RSA_1024: Encryption_NONE_Params(),
        SSH_ED448: Encryption_NONE_Params(),
    },
}


class PUTTY_ENCRYPTION_PARAMS_DICT(TypedDict):
    aes256_cbc: dict[KEY_NAMES_T, Encryption_AES256_CBC]
    none: dict[KEY_NAMES_T, Encryption_NONE]


PUTTY_ENCRYPTION_PARAMS: PUTTY_ENCRYPTION_PARAMS_DICT = {
    ENC_AES256_CBC: {
        SSH_ED25519: Encryption_AES256_CBC(
            key_derivation=ArgonID.ID,
            argon2_memory=MemoryCost(8192),
            argon2_passes=TimeCost(21),
            argon2_parallelism=Parallelism(1),
        ),
        SSH_RSA_1024: Encryption_AES256_CBC(
            key_derivation=ArgonID.ID,
            argon2_memory=MemoryCost(8192),
            argon2_passes=TimeCost(21),
            argon2_parallelism=Parallelism(1),
        ),
        SSH_ED448: Encryption_AES256_CBC(
            key_derivation=ArgonID.ID,
            argon2_memory=MemoryCost(8192),
            argon2_passes=TimeCost(21),
            argon2_parallelism=Parallelism(1),
        ),
    },
    ENC_NONE: {
        SSH_ED25519: Encryption_NONE(),
        SSH_RSA_1024: Encryption_NONE(),
        SSH_ED448: Encryption_NONE(),
    },
}


PUTTY_FILE_V3 = {
    ENC_AES256_CBC: {
        SSH_ED25519: PuttyFileV3(
            key_type="ssh-ed25519",
            comment="RFC8032 7.1 Test Vector 1",
            public_lines=b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a",
            decryption_params=Encryption_AES256_CBC_Params(
                argon2_params=Argon2Params(
                    type=ArgonID.ID,
                    memory_cost=MemoryCost(8192),
                    time_cost=TimeCost(21),
                    parallelism=Parallelism(1),
                    salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
                ),
            ),
            private_lines=EncryptedBytes(
                value=b"\xdcI\x85e\xdb)\xe6Q\xf7o\x938h\x7f\xa4\xc3\x8d|\xc9\x82\xc8\xdf\x8eh\xb0}\xa0\x83\xd8\x92\xde\xf6-\xdcD\xd7\t\xbb\xd8K\xf5}9\xa1\x98\x99\xce\xcc"
            ),
            mac=Mac(
                private_mac=b"}h\xef\xb8\xce\x10\xc7xz\xd4\xdc\x97=\xab\xb5#;!\xd2\x06\x92\xbe\xfb'\x8fn\xe8\x9e>\x13N\xef"
            ),
        ),
        SSH_RSA_1024: PuttyFileV3(
            key_type="ssh-rsa",
            comment="testRSA1024",
            public_lines=b'\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?',
            decryption_params=Encryption_AES256_CBC_Params(
                argon2_params=Argon2Params(
                    type=ArgonID.ID,
                    memory_cost=MemoryCost(8192),
                    time_cost=TimeCost(21),
                    parallelism=Parallelism(1),
                    salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
                ),
            ),
            private_lines=EncryptedBytes(
                value=b"M\x8e\xec!\x0f\x14\xbfO\xb6\xad\xf1'T\xdf\xc30\x83\xba\xaf0\xe5\xd5K\x1c\x80\xd66\xe9\x12B\xef\xce\xd4\xcdhe\xdd\x9d\\}\xaa\xca\x9cr\x90_|\x10n\xcf\xbdb\xb3\x01V\x86\x08\x15_\x94)\x88\x01\xf0lOu\x1d\xb2\x9dq<\x80\xa5 \rX\xe4\x81\xa6q}\xbc\x14\xb9[Z\xd6\x14\x1d.I\xfc\x9b\xfc\x9b\xeaM\xc9\xf0G\xdc\xe0\x91F\xb2\xb4\xe4\xbdS\xc6j\r-<\xc3\xbc\x97\xc1\xbd\xf9 \xe0\x0197\xb7=V\xbdQ\xe8\xf0\x94\xef\xb3h\x86\x86xL\x97\xe6?\xf4+\x18\x96_\x7f\xbe\x9d\x94j\x1c\x9c\xb9\x97\x01\xbb\xf1k\xf6\xdd\x8dQZ\xab\xc93\xab\x96|\x13'1\x10m\xe2\xda<{>\xf5~\xfa\x94l\xe0{O\xd1\xe0\xb1\xdc \x11\xb5~\xde\x14\xc1\xfb\x1c|\xa3A-)\xdcN#\xb0\x1eq\xd4\xf7\xa1\xd8:/\xb5\xf2\xe0\x06\xc2#p\"i\xf2\xf5\xe0\xf6\xf2\xc0\xed \x15\"<\xcf\x10-\x91\x8dmj\x14\x89\xb9\x04\x0bO\xac\x95\xbf\xed\x96\x14\x9eT?\xcfL\x03\xf40\xa0v\xac(\xe3\xecJ\x9c\x98h\xcbB\xbb\x8a-\xcf\xb5\xd5o\xeeQ\x80\xa1\x8c\xf2\x13\xad\xcfs_\xf7f;\x86\xd6\xb8\xb9\xc50\xfaG\xa4\n%\xeb\xe7|t\x0b\xd9\xbb\x8d\xfa>\x8b\x84y\x82\xf67t\x82\xb4iU\xf74\xa0\xca\xfc\xf02j\xb1\xc7\xd6\xcbG\xc4\xbf\x11>U\xfd"
            ),
            mac=Mac(
                private_mac=b"\xe17<\xd5\r\xec\xfcoY\x170\xbbB\xcf\xae\xd1\xe6\x91\xd2C\xc4\x02eE)|\x89\x0e4\x94'\x14"
            ),
        ),
        SSH_ED448: PuttyFileV3(
            key_type="ssh-ed448",
            comment="RFC8032 7.4 Test Vector 1",
            public_lines=b"\x00\x00\x00\tssh-ed448\x00\x00\x009_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80",
            decryption_params=Encryption_AES256_CBC_Params(
                argon2_params=Argon2Params(
                    type=ArgonID.ID,
                    memory_cost=MemoryCost(8192),
                    time_cost=TimeCost(21),
                    parallelism=Parallelism(1),
                    salt=Salt(b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"),
                ),
            ),
            private_lines=EncryptedBytes(
                value=b'\xef\x1aOK\xb8\xea"#\xbf!\xa4\x03\x14e\x98\x8dqZ\x1d/\xe0\xcd\xcb\xe4g"%\x12\xa9\xc8]\x13\x8f\xf5\xf9rl\x81\xd2\xe7vV\x85>D\xfbp\x06\xee\xd8\xeb\t\x19bnm\xc5?\xe5\xd5Iax\x84'
            ),
            mac=Mac(
                private_mac=b"\xad\xf1?\x15\xb4\xf9\x8fV}N\xd9\xbd9\x88\x10\xb4GN\x01\xf2\x82h\xe7z\xd2\xefZcP\x90{\xec"
            ),
        ),
    },
    ENC_NONE: {
        SSH_ED25519: PuttyFileV3(
            key_type="ssh-ed25519",
            comment="RFC8032 7.1 Test Vector 1",
            public_lines=b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a",
            decryption_params=Encryption_NONE_Params(),
            private_lines=EncryptedBytes(
                value=b"\x00\x00\x00 \x9da\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`"
            ),
            mac=Mac(
                private_mac=b'"\xcf\x83\x08\xed\x9b\xbfDv\x0b\xe8\xd3\xfa9\x1c\xf2\x03\x9f\x06\x9b0\x14Nl\x8db\xc4X\x10\xc1ij'
            ),
        ),
        SSH_RSA_1024: PuttyFileV3(
            key_type="ssh-rsa",
            comment="testRSA1024",
            public_lines=b'\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x00\x81\x00\xb0\xd1\x83R\xa8\x8fS\xd5QoF\xc2\x0ez6}}\xe8\x8a\xcfT\xa0\x19\xf6\xde\xf5z\xb9\xb4L\xed\xdb"B\xb1\xbc\xa0\xfb\x1b\\\xb8+06\x17jc\x905d\xde\xc6\xebA\xdb/\x8f\xc7\x87\xf4\xe5.\x11I\xe33GW)s\xf6`\xc3\xc7|\xa9\xe0\x82\x1c+i[\xe7\xae\x9d}0\xf4\x07\x91\x10\xf4\x8a\xaeo\x8bp-GK)\x00\x81\x7f(f$\x9b\xec\x12\xa2\xb1\x9b\x82xAh\x08\xf8\x1a\xe1\xfc\xf9\xb7w\x8ab?',
            decryption_params=Encryption_NONE_Params(),
            private_lines=EncryptedBytes(
                value=b"\x00\x00\x00\x80H.\x9f\x8f\xa4\xe4-\xf3\ru\x81\xcbB\xa1\xbd\x90\xe9O\x7f+8~\xcbZ\xae\x96C\xed\x7f\x9fP\x12\x7f\x1f\xfe\xf2\xe4<\xded\xb1\x82`\x02\x14\xf9\x07\x80\x1dk\xfaM\xf6HB4^[\xb42\xd3DE%\xd80\x16T\xc5D+\n^\x11\xb9\xc7\xe2\x01\xfa2\xf4\x1a\xba\xf4\xf0\xa6\xe0<\xf0\xe0\xcb\x82f\xc6*\xd1\x1d\x95mS\xc9FnH\x99_\xea&\x0c\x856\xf0A\xcb5b\xfa\xacQ\x1cMf\xa8\xfe\xd1\x11\xb2\x91\x00\x00\x00A\x00\xe9\xd8nM\xc3J\x98Z~\xc7ZoT\xa7\\\xe4Q9\xe4R@\xb3\x86\xabq\x1d\xb7\x91\xbc\xd9\x87\x18\xa1;\xaf!\x8c$I6Fh\x07V\xcbP\xa6\xcb\xee\x15\x8e%!D\x99\x120\x1c\rAI\x11\x18E\x00\x00\x00A\x00\xc1\x91\xfa;U\x0b9\x1a|\xb0r\x83v'r\x95\xe6\x1ceO\x0b\xef/X\xdc\xe5\xc9b\xa1\x0b}\xd7_\x06\x01Te\xe5Pv\xe4f&>\xeb\xca\xed \xd2\xeb\xab91>\x8b\xc5g2\x0f\xe8\xb2\xdcb\xb3\x00\x00\x00A\x00\xb9\x9d\x7f\x8fMME_\x1f\xbaF-\x99\n.\x84\x8cB\x8c\x1e\xbe\xe0\x1d\xc0\x01\x84\xc8\xa7e\x83\xad7\x9fi\xad\xafTuT0\xf6<BS\xd1\xbbx\xcc\x9b\xd22d4\x00\x80\xb8L\x1a\x91}\xe0\x8bn\xdb"
            ),
            mac=Mac(
                private_mac=b"\x8b\x0c6\xad\xd1\x82c\xe2\x13\x1e\x94O\xc4\xa7\xe1MW\x9e\xae\xbd\x96IW\x7f|\xb1\x85\xc5\xf5Wc\xe5"
            ),
        ),
        SSH_ED448: PuttyFileV3(
            key_type="ssh-ed448",
            comment="RFC8032 7.4 Test Vector 1",
            public_lines=b"\x00\x00\x00\tssh-ed448\x00\x00\x009_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80",
            decryption_params=Encryption_NONE_Params(),
            private_lines=EncryptedBytes(
                value=b"\x00\x00\x009l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9["
            ),
            mac=Mac(
                private_mac=b"H\xc2\x1e\xa5\x17\x15\n7\x97 \x96\x89\x0e/7\xb7\xde|2h\x931`t \xb8\x02V\x831\xfe\x1c"
            ),
        ),
    },
}

PUTTY_PPK_V3 = {
    ENC_AES256_CBC: {
        SSH_ED25519: b"""PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: RFC8032 7.1 Test Vector 1
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3
B1Ea
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 0102030405060708090a0b0c0d0e0f10
Private-Lines: 1
3EmFZdsp5lH3b5M4aH+kw418yYLI345osH2gg9iS3vYt3ETXCbvYS/V9OaGYmc7M
Private-MAC: 7d68efb8ce10c7787ad4dc973dabb5233b21d20692befb278f6ee89e3e134eef
""",
        SSH_RSA_1024: b"""PuTTY-User-Key-File-3: ssh-rsa
Encryption: aes256-cbc
Comment: testRSA1024
Public-Lines: 4
AAAAB3NzaC1yc2EAAAADAQABAAAAgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe
9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDD
x3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh
/Pm3d4piPw==
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 0102030405060708090a0b0c0d0e0f10
Private-Lines: 8
TY7sIQ8Uv0+2rfEnVN/DMIO6rzDl1UscgNY26RJC787UzWhl3Z1cfarKnHKQX3wQ
bs+9YrMBVoYIFV+UKYgB8GxPdR2ynXE8gKUgDVjkgaZxfbwUuVta1hQdLkn8m/yb
6k3J8Efc4JFGsrTkvVPGag0tPMO8l8G9+SDgATk3tz1WvVHo8JTvs2iGhnhMl+Y/
9CsYll9/vp2UahycuZcBu/Fr9t2NUVqryTOrlnwTJzEQbeLaPHs+9X76lGzge0/R
4LHcIBG1ft4UwfscfKNBLSncTiOwHnHU96HYOi+18uAGwiNwImny9eD28sDtIBUi
PM8QLZGNbWoUibkEC0+slb/tlhSeVD/PTAP0MKB2rCjj7EqcmGjLQruKLc+11W/u
UYChjPITrc9zX/dmO4bWuLnFMPpHpAol6+d8dAvZu436PouEeYL2N3SCtGlV9zSg
yvzwMmqxx9bLR8S/ET5V/Q==
Private-MAC: e1373cd50decfc6f591730bb42cfaed1e691d243c4026545297c890e34942714
""",
        SSH_ED448: b"""PuTTY-User-Key-File-3: ssh-ed448
Encryption: aes256-cbc
Comment: RFC8032 7.4 Test Vector 1
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADlf10SbWbRh/Sznh+xhatRqHaE0JIWnDh+KDqddgOln
eO3xJHabRscGG9Z4PfHlD2zR+hq+r+glYYA=
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 0102030405060708090a0b0c0d0e0f10
Private-Lines: 2
7xpPS7jqIiO/IaQDFGWYjXFaHS/gzcvkZyIlEqnIXROP9flybIHS53ZWhT5E+3AG
7tjrCRlibm3FP+XVSWF4hA==
Private-MAC: adf13f15b4f98f567d4ed9bd398810b4474e01f28268e77ad2ef5a6350907bec
""",
    },
    ENC_NONE: {
        SSH_ED25519: b"""PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: RFC8032 7.1 Test Vector 1
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3
B1Ea
Private-Lines: 1
AAAAIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
Private-MAC: 22cf8308ed9bbf44760be8d3fa391cf2039f069b30144e6c8d62c45810c1696a
""",
        SSH_RSA_1024: b"""PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: testRSA1024
Public-Lines: 4
AAAAB3NzaC1yc2EAAAADAQABAAAAgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe
9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDD
x3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh
/Pm3d4piPw==
Private-Lines: 8
AAAAgEgun4+k5C3zDXWBy0KhvZDpT38rOH7LWq6WQ+1/n1ASfx/+8uQ83mSxgmAC
FPkHgB1r+k32SEI0Xlu0MtNERSXYMBZUxUQrCl4RucfiAfoy9Bq69PCm4Dzw4MuC
ZsYq0R2VbVPJRm5ImV/qJgyFNvBByzVi+qxRHE1mqP7REbKRAAAAQQDp2G5Nw0qY
Wn7HWm9Up1zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZ
EjAcDUFJERhFAAAAQQDBkfo7VQs5GnywcoN2J3KV5hxlTwvvL1jc5clioQt9118G
AVRl5VB25GYmPuvK7SDS66s5MT6LxWcyD+iy3GKzAAAAQQC5nX+PTU1FXx+6Ri2Z
Ci6EjEKMHr7gHcABhMinZYOtN59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3g
i27b
Private-MAC: 8b0c36add18263e2131e944fc4a7e14d579eaebd9649577f7cb185c5f55763e5
""",
        SSH_ED448: b"""PuTTY-User-Key-File-3: ssh-ed448
Encryption: none
Comment: RFC8032 7.4 Test Vector 1
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADlf10SbWbRh/Sznh+xhatRqHaE0JIWnDh+KDqddgOln
eO3xJHabRscGG9Z4PfHlD2zR+hq+r+glYYA=
Private-Lines: 2
AAAAOWyCpWLLgI0Q1jK+ichRPr9skp803fqMn2PJlg7240ijUoyKP8wvBE45o/xb
lEkvjwMudUmiAJj5Ww==
Private-MAC: 48c21ea517150a37972096890e2f37b7de7c32689331607420b802568331fe1c
""",
    },
}

# endregion
