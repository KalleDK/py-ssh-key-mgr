from builtins import bytes, dict
from typing import TypedDict

from ssh_key_mgr import putty
from ssh_key_mgr.encryption import (
    IV,
    Argon2Params,
    ArgonID,
    CipherKey,
    EncryptedBytes,
    MemoryCost,
    Parallelism,
    Salt,
    SecretBytes,
    TimeCost,
)
from ssh_key_mgr.putty.checksum import Mac
from ssh_key_mgr.putty.encryption.enc_aes256_cbc_argon2 import Decryption_AES256_CBC_Params, Encryption_AES256_CBC
from ssh_key_mgr.putty.encryption.enc_none import Decryption_NONE_Params, Encryption_NONE
from ssh_key_mgr.putty.file import PuttyFileV3
from ssh_key_mgr.putty.keys import (
    PuttyKeyEd448,
    PuttyKeyEd25519,
    PuttyKeyPair,
    PuttyKeyPairRSA,
    PuttyPrivateKeyEd448,
    PuttyPrivateKeyEd25519,
    PuttyPrivateKeyRSA,
    PuttyPublicKey,
    PuttyPublicKeyEd448,
    PuttyPublicKeyEd25519,
    PuttyPublicKeyRSA,
)


class AesTestVectorT(TypedDict):
    CipherKey: CipherKey
    IV: IV
    Decrypted: bytes
    Encrypted: EncryptedBytes


class AES_TESTS_DICT(TypedDict):
    CipherKey: CipherKey
    IV: IV
    Decrypted: bytes
    Encrypted: EncryptedBytes


PUTTY_AES: dict[str, AES_TESTS_DICT] = {
    "TestVector_1": {
        "CipherKey": CipherKey(bytes.fromhex("3624b653c1264e7f192df86a7438d5191cc4c9dac98ca8dd74c2da8b9ecfe515")),
        "IV": IV(bytes.fromhex("efb583d376b19d92d81e75bea335768d")),
        "Decrypted": bytes.fromhex("6465637279707465645f310102030405"),
        "Encrypted": EncryptedBytes(value=bytes.fromhex("441338588b8fb82cef1884382f6902e4")),
    },
    "TestVector_2": {
        "CipherKey": CipherKey(bytes.fromhex("88cc50d8019d6cdad3d0e146add113224a0b683d573eaa9b59b09a3aa3a1cdf8")),
        "IV": IV(bytes.fromhex("fc2c0c139d5b71c45a339f91a8196190")),
        "Decrypted": bytes.fromhex("6465637279707465645f320102030405"),
        "Encrypted": EncryptedBytes(value=bytes.fromhex("d4fd2996e633996fcaaa78d05f184266")),
    },
}


class PUTTY_ARGON_DICT(TypedDict):
    Params: Argon2Params
    Passphrase: SecretBytes
    Hash: bytes
    HashLength: int


PUTTY_ARGON: dict[str, PUTTY_ARGON_DICT] = {
    "TestVector_16": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
        ),
        "Passphrase": SecretBytes(bytes.fromhex("706173737068726173655f30")),
        "Hash": bytes.fromhex("6a7c65d3b6c69b449fd0dd1c1fe5ff35"),
        "HashLength": 16,
    },
    "TestVector_24": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
        ),
        "Passphrase": SecretBytes(bytes.fromhex("706173737068726173655f31")),
        "Hash": bytes.fromhex("e1fd811a215210e37188466126f36702831ccd960987a390"),
        "HashLength": 24,
    },
    "TestVector_32": {
        "Params": Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
        ),
        "Passphrase": SecretBytes(bytes.fromhex("706173737068726173655f32")),
        "Hash": bytes.fromhex("ca9b78c8f0944c8db3c05b9b95bdd3b8fb19a5dfb6aa0a4c8d3966f8a38e80ee"),
        "HashLength": 32,
    },
}
PUTTY_PUBLIC_KEYS: dict[str, PuttyPublicKey] = {
    "ED25519": PuttyPublicKeyEd25519(
        key=bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    ),
    "ED448": PuttyPublicKeyEd448(
        key=bytes.fromhex(
            "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
        )
    ),
    "RSA_1024": PuttyPublicKeyRSA(
        E=65537,
        N=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    ),
}
PUTTY_PUBLIC_KEY_WIRES: dict[str, bytes] = {
    "ED25519": bytes.fromhex(
        "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ),
    "ED448": bytes.fromhex(
        "000000097373682d6564343438000000395fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
    ),
    "RSA_1024": bytes.fromhex(
        "000000077373682d727361000000030100010000008100b0d18352a88f53d5516f46c20e7a367d7de88acf54a019f6def57ab9b44ceddb2242b1bca0fb1b5cb82b3036176a63903564dec6eb41db2f8fc787f4e52e1149e33347572973f660c3c77ca9e0821c2b695be7ae9d7d30f4079110f48aae6f8b702d474b2900817f2866249bec12a2b19b8278416808f81ae1fcf9b7778a623f"
    ),
}
PUTTY_PRIVATE_KEY_WIRES: dict[str, bytes] = {
    "ED25519": bytes.fromhex("000000209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    "ED448": bytes.fromhex(
        "000000396c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
    ),
    "RSA_1024": bytes.fromhex(
        "00000080482e9f8fa4e42df30d7581cb42a1bd90e94f7f2b387ecb5aae9643ed7f9f50127f1ffef2e43cde64b182600214f907801d6bfa4df64842345e5bb432d3444525d8301654c5442b0a5e11b9c7e201fa32f41abaf4f0a6e03cf0e0cb8266c62ad11d956d53c9466e48995fea260c8536f041cb3562faac511c4d66a8fed111b2910000004100e9d86e4dc34a985a7ec75a6f54a75ce45139e45240b386ab711db791bcd98718a13baf218c24493646680756cb50a6cbee158e2521449912301c0d41491118450000004100c191fa3b550b391a7cb0728376277295e61c654f0bef2f58dce5c962a10b7dd75f06015465e55076e466263eebcaed20d2ebab39313e8bc567320fe8b2dc62b30000004100b99d7f8f4d4d455f1fba462d990a2e848c428c1ebee01dc00184c8a76583ad379f69adaf54755430f63c4253d1bb78cc9bd23264340080b84c1a917de08b6edb"
    ),
}
PUTTY_KEY_NAMES: list[str] = ["ED25519", "ED448", "RSA_1024"]
PUTTY_ENC_NAMES: list[str] = ["NONE", "AES256_CBC"]


class PuttyKeyEncryptionDict(TypedDict):
    Params: putty.Encryption
    Passphrase: SecretBytes | None
    FileObj: putty.PuttyFileV3
    File: str


class PuttyKeyTestDict(TypedDict):
    Encryptions: dict[str, PuttyKeyEncryptionDict]
    Obj: PuttyKeyPair
    PublicWire: bytes
    PrivateWire: bytes


PUTTY_KEY_TESTS: dict[str, PuttyKeyTestDict] = {
    "ED25519": {
        "Obj": PuttyKeyEd25519(
            public=PuttyPublicKeyEd25519(
                key=bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            ),
            private=PuttyPrivateKeyEd25519(
                key=bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            ),
            comment="RFC8032 7.1 Test Vector 1",
        ),
        "PublicWire": bytes.fromhex(
            "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ),
        "PrivateWire": bytes.fromhex("000000209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
        "Encryptions": {
            "NONE": {
                "Params": Encryption_NONE(),
                "Passphrase": None,
                "FileObj": PuttyFileV3(
                    key_type="ssh-ed25519",
                    comment="RFC8032 7.1 Test Vector 1",
                    decryption_params=Decryption_NONE_Params(),
                    public_lines=bytes.fromhex(
                        "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex("000000209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("22cf8308ed9bbf44760be8d3fa391cf2039f069b30144e6c8d62c45810c1696a")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: RFC8032 7.1 Test Vector 1\nPublic-Lines: 2\nAAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3\nB1Ea\nPrivate-Lines: 1\nAAAAIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g\nPrivate-MAC: 22cf8308ed9bbf44760be8d3fa391cf2039f069b30144e6c8d62c45810c1696a\n",
            },
            "AES256_CBC": {
                "Params": Encryption_AES256_CBC(
                    key_derivation=ArgonID.ID,
                    argon2_memory=MemoryCost(8192),
                    argon2_passes=TimeCost(21),
                    argon2_parallelism=Parallelism(1),
                ),
                "Passphrase": SecretBytes(bytes.fromhex("50757474794b657945643235353139")),
                "FileObj": PuttyFileV3(
                    key_type="ssh-ed25519",
                    comment="RFC8032 7.1 Test Vector 1",
                    decryption_params=Decryption_AES256_CBC_Params(
                        argon2_params=Argon2Params(
                            type=ArgonID.ID,
                            memory_cost=MemoryCost(8192),
                            time_cost=TimeCost(21),
                            parallelism=Parallelism(1),
                            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
                        )
                    ),
                    public_lines=bytes.fromhex(
                        "0000000b7373682d6564323535313900000020d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex(
                            "e20571282e0ad42f865f534bdfd88d579452cd4adc1d20ca84ca731ae795ab3051805030bfe157dacfe4c6204285c383"
                        )
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("3fa770f8a4e62e47ac1159bb57a575464a171d38ffac1ad9e28c3a080a5e91de")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: RFC8032 7.1 Test Vector 1\nPublic-Lines: 2\nAAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3\nB1Ea\nKey-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 21\nArgon2-Parallelism: 1\nArgon2-Salt: 0102030405060708090a0b0c0d0e0f10\nPrivate-Lines: 1\n4gVxKC4K1C+GX1NL39iNV5RSzUrcHSDKhMpzGueVqzBRgFAwv+FX2s/kxiBChcOD\nPrivate-MAC: 3fa770f8a4e62e47ac1159bb57a575464a171d38ffac1ad9e28c3a080a5e91de\n",
            },
        },
    },
    "ED448": {
        "Obj": PuttyKeyEd448(
            public=PuttyPublicKeyEd448(
                key=bytes.fromhex(
                    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                )
            ),
            private=PuttyPrivateKeyEd448(
                key=bytes.fromhex(
                    "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
                )
            ),
            comment="RFC8032 7.4 Test Vector 1",
        ),
        "PublicWire": bytes.fromhex(
            "000000097373682d6564343438000000395fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
        ),
        "PrivateWire": bytes.fromhex(
            "000000396c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
        ),
        "Encryptions": {
            "NONE": {
                "Params": Encryption_NONE(),
                "Passphrase": None,
                "FileObj": PuttyFileV3(
                    key_type="ssh-ed448",
                    comment="RFC8032 7.4 Test Vector 1",
                    decryption_params=Decryption_NONE_Params(),
                    public_lines=bytes.fromhex(
                        "000000097373682d6564343438000000395fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex(
                            "000000396c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
                        )
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("48c21ea517150a37972096890e2f37b7de7c32689331607420b802568331fe1c")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-ed448\nEncryption: none\nComment: RFC8032 7.4 Test Vector 1\nPublic-Lines: 2\nAAAACXNzaC1lZDQ0OAAAADlf10SbWbRh/Sznh+xhatRqHaE0JIWnDh+KDqddgOln\neO3xJHabRscGG9Z4PfHlD2zR+hq+r+glYYA=\nPrivate-Lines: 2\nAAAAOWyCpWLLgI0Q1jK+ichRPr9skp803fqMn2PJlg7240ijUoyKP8wvBE45o/xb\nlEkvjwMudUmiAJj5Ww==\nPrivate-MAC: 48c21ea517150a37972096890e2f37b7de7c32689331607420b802568331fe1c\n",
            },
            "AES256_CBC": {
                "Params": Encryption_AES256_CBC(
                    key_derivation=ArgonID.ID,
                    argon2_memory=MemoryCost(8192),
                    argon2_passes=TimeCost(21),
                    argon2_parallelism=Parallelism(1),
                ),
                "Passphrase": SecretBytes(bytes.fromhex("50757474794b65794564343438")),
                "FileObj": PuttyFileV3(
                    key_type="ssh-ed448",
                    comment="RFC8032 7.4 Test Vector 1",
                    decryption_params=Decryption_AES256_CBC_Params(
                        argon2_params=Argon2Params(
                            type=ArgonID.ID,
                            memory_cost=MemoryCost(8192),
                            time_cost=TimeCost(21),
                            parallelism=Parallelism(1),
                            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
                        )
                    ),
                    public_lines=bytes.fromhex(
                        "000000097373682d6564343438000000395fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex(
                            "1017df3d483d131e570e93a63e57c9654fd42a553e8c5b99eb2ba3a9aea3c9c46811ad2ced92453ec5e0479f134651fd8da41a373d6347e07e98286edcbd0d70"
                        )
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("38f758df0a5356612d5a46d46126e1abb7624c68a8e09e27aae205562828bd33")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-ed448\nEncryption: aes256-cbc\nComment: RFC8032 7.4 Test Vector 1\nPublic-Lines: 2\nAAAACXNzaC1lZDQ0OAAAADlf10SbWbRh/Sznh+xhatRqHaE0JIWnDh+KDqddgOln\neO3xJHabRscGG9Z4PfHlD2zR+hq+r+glYYA=\nKey-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 21\nArgon2-Parallelism: 1\nArgon2-Salt: 0102030405060708090a0b0c0d0e0f10\nPrivate-Lines: 2\nEBffPUg9Ex5XDpOmPlfJZU/UKlU+jFuZ6yujqa6jycRoEa0s7ZJFPsXgR58TRlH9\njaQaNz1jR+B+mChu3L0NcA==\nPrivate-MAC: 38f758df0a5356612d5a46d46126e1abb7624c68a8e09e27aae205562828bd33\n",
            },
        },
    },
    "RSA_1024": {
        "Obj": PuttyKeyPairRSA(
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
        "PublicWire": bytes.fromhex(
            "000000077373682d727361000000030100010000008100b0d18352a88f53d5516f46c20e7a367d7de88acf54a019f6def57ab9b44ceddb2242b1bca0fb1b5cb82b3036176a63903564dec6eb41db2f8fc787f4e52e1149e33347572973f660c3c77ca9e0821c2b695be7ae9d7d30f4079110f48aae6f8b702d474b2900817f2866249bec12a2b19b8278416808f81ae1fcf9b7778a623f"
        ),
        "PrivateWire": bytes.fromhex(
            "00000080482e9f8fa4e42df30d7581cb42a1bd90e94f7f2b387ecb5aae9643ed7f9f50127f1ffef2e43cde64b182600214f907801d6bfa4df64842345e5bb432d3444525d8301654c5442b0a5e11b9c7e201fa32f41abaf4f0a6e03cf0e0cb8266c62ad11d956d53c9466e48995fea260c8536f041cb3562faac511c4d66a8fed111b2910000004100e9d86e4dc34a985a7ec75a6f54a75ce45139e45240b386ab711db791bcd98718a13baf218c24493646680756cb50a6cbee158e2521449912301c0d41491118450000004100c191fa3b550b391a7cb0728376277295e61c654f0bef2f58dce5c962a10b7dd75f06015465e55076e466263eebcaed20d2ebab39313e8bc567320fe8b2dc62b30000004100b99d7f8f4d4d455f1fba462d990a2e848c428c1ebee01dc00184c8a76583ad379f69adaf54755430f63c4253d1bb78cc9bd23264340080b84c1a917de08b6edb"
        ),
        "Encryptions": {
            "NONE": {
                "Params": Encryption_NONE(),
                "Passphrase": None,
                "FileObj": PuttyFileV3(
                    key_type="ssh-rsa",
                    comment="testRSA1024",
                    decryption_params=Decryption_NONE_Params(),
                    public_lines=bytes.fromhex(
                        "000000077373682d727361000000030100010000008100b0d18352a88f53d5516f46c20e7a367d7de88acf54a019f6def57ab9b44ceddb2242b1bca0fb1b5cb82b3036176a63903564dec6eb41db2f8fc787f4e52e1149e33347572973f660c3c77ca9e0821c2b695be7ae9d7d30f4079110f48aae6f8b702d474b2900817f2866249bec12a2b19b8278416808f81ae1fcf9b7778a623f"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex(
                            "00000080482e9f8fa4e42df30d7581cb42a1bd90e94f7f2b387ecb5aae9643ed7f9f50127f1ffef2e43cde64b182600214f907801d6bfa4df64842345e5bb432d3444525d8301654c5442b0a5e11b9c7e201fa32f41abaf4f0a6e03cf0e0cb8266c62ad11d956d53c9466e48995fea260c8536f041cb3562faac511c4d66a8fed111b2910000004100e9d86e4dc34a985a7ec75a6f54a75ce45139e45240b386ab711db791bcd98718a13baf218c24493646680756cb50a6cbee158e2521449912301c0d41491118450000004100c191fa3b550b391a7cb0728376277295e61c654f0bef2f58dce5c962a10b7dd75f06015465e55076e466263eebcaed20d2ebab39313e8bc567320fe8b2dc62b30000004100b99d7f8f4d4d455f1fba462d990a2e848c428c1ebee01dc00184c8a76583ad379f69adaf54755430f63c4253d1bb78cc9bd23264340080b84c1a917de08b6edb"
                        )
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("8b0c36add18263e2131e944fc4a7e14d579eaebd9649577f7cb185c5f55763e5")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: testRSA1024\nPublic-Lines: 4\nAAAAB3NzaC1yc2EAAAADAQABAAAAgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe\n9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDD\nx3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh\n/Pm3d4piPw==\nPrivate-Lines: 8\nAAAAgEgun4+k5C3zDXWBy0KhvZDpT38rOH7LWq6WQ+1/n1ASfx/+8uQ83mSxgmAC\nFPkHgB1r+k32SEI0Xlu0MtNERSXYMBZUxUQrCl4RucfiAfoy9Bq69PCm4Dzw4MuC\nZsYq0R2VbVPJRm5ImV/qJgyFNvBByzVi+qxRHE1mqP7REbKRAAAAQQDp2G5Nw0qY\nWn7HWm9Up1zkUTnkUkCzhqtxHbeRvNmHGKE7ryGMJEk2RmgHVstQpsvuFY4lIUSZ\nEjAcDUFJERhFAAAAQQDBkfo7VQs5GnywcoN2J3KV5hxlTwvvL1jc5clioQt9118G\nAVRl5VB25GYmPuvK7SDS66s5MT6LxWcyD+iy3GKzAAAAQQC5nX+PTU1FXx+6Ri2Z\nCi6EjEKMHr7gHcABhMinZYOtN59pra9UdVQw9jxCU9G7eMyb0jJkNACAuEwakX3g\ni27b\nPrivate-MAC: 8b0c36add18263e2131e944fc4a7e14d579eaebd9649577f7cb185c5f55763e5\n",
            },
            "AES256_CBC": {
                "Params": Encryption_AES256_CBC(
                    key_derivation=ArgonID.ID,
                    argon2_memory=MemoryCost(8192),
                    argon2_passes=TimeCost(21),
                    argon2_parallelism=Parallelism(1),
                ),
                "Passphrase": SecretBytes(bytes.fromhex("50757474794b657950616972525341")),
                "FileObj": PuttyFileV3(
                    key_type="ssh-rsa",
                    comment="testRSA1024",
                    decryption_params=Decryption_AES256_CBC_Params(
                        argon2_params=Argon2Params(
                            type=ArgonID.ID,
                            memory_cost=MemoryCost(8192),
                            time_cost=TimeCost(21),
                            parallelism=Parallelism(1),
                            salt=Salt(bytes.fromhex("0102030405060708090a0b0c0d0e0f10")),
                        )
                    ),
                    public_lines=bytes.fromhex(
                        "000000077373682d727361000000030100010000008100b0d18352a88f53d5516f46c20e7a367d7de88acf54a019f6def57ab9b44ceddb2242b1bca0fb1b5cb82b3036176a63903564dec6eb41db2f8fc787f4e52e1149e33347572973f660c3c77ca9e0821c2b695be7ae9d7d30f4079110f48aae6f8b702d474b2900817f2866249bec12a2b19b8278416808f81ae1fcf9b7778a623f"
                    ),
                    private_lines=EncryptedBytes(
                        value=bytes.fromhex(
                            "778dc84a92823599491916ee3b5d63c8bbc65636e4352aabbfa30914e9060414d54297abdbf329b30d6e79de745a5e7c0266a45b4d347ad2cdd46f4499087fd08f184d3853e9c4ee9d085f84ee086617c051776329bca40d1c6ca99f2f3368f4d0c8d19f726ac8259f71e823c5bc1b068142753f0c89376e895bab1e481c5f552f3dded7d34c171d5cc8bfa5660845b72dfb57ed11afcf22795f1bb8658bb3c0d864acf2daedd6b46624fba3524635a4a2593ddaf814045fbfb63ce3b39d3fe856880734165fc6646a74e2130f78de6dd6d6a8fb8ff203807da57ff96f8ff71cf4cdf60dff08ce9f68de19e839f42adca5aa82de22987b52a4606e71a1d4067a0f527791a11de8e7d96f7e1e57d7cb791083d8ecb57fedc2c011637020ae7c90fb24365cf39590ca90d3e1638064edcf8a8a68bc5b01d76389ed87140e5a27cf294bc30605e4b6030ae534cb320d55e5710396606a4ca7ab31befb83ae845fc6"
                        )
                    ),
                    mac=Mac(
                        private_mac=bytes.fromhex("084bc537318a4c44fbb728e5e6a53b60f9225806541f5fd86ccc13f78c15c1bf")
                    ),
                ),
                "File": "PuTTY-User-Key-File-3: ssh-rsa\nEncryption: aes256-cbc\nComment: testRSA1024\nPublic-Lines: 4\nAAAAB3NzaC1yc2EAAAADAQABAAAAgQCw0YNSqI9T1VFvRsIOejZ9feiKz1SgGfbe\n9Xq5tEzt2yJCsbyg+xtcuCswNhdqY5A1ZN7G60HbL4/Hh/TlLhFJ4zNHVylz9mDD\nx3yp4IIcK2lb566dfTD0B5EQ9Iqub4twLUdLKQCBfyhmJJvsEqKxm4J4QWgI+Brh\n/Pm3d4piPw==\nKey-Derivation: Argon2id\nArgon2-Memory: 8192\nArgon2-Passes: 21\nArgon2-Parallelism: 1\nArgon2-Salt: 0102030405060708090a0b0c0d0e0f10\nPrivate-Lines: 8\nd43ISpKCNZlJGRbuO11jyLvGVjbkNSqrv6MJFOkGBBTVQper2/Mpsw1ued50Wl58\nAmakW000etLN1G9EmQh/0I8YTThT6cTunQhfhO4IZhfAUXdjKbykDRxsqZ8vM2j0\n0MjRn3JqyCWfcegjxbwbBoFCdT8MiTduiVurHkgcX1UvPd7X00wXHVzIv6VmCEW3\nLftX7RGvzyJ5Xxu4ZYuzwNhkrPLa7da0ZiT7o1JGNaSiWT3a+BQEX7+2POOznT/o\nVogHNBZfxmRqdOITD3jebdbWqPuP8gOAfaV/+W+P9xz0zfYN/wjOn2jeGeg59Crc\npaqC3iKYe1KkYG5xodQGeg9Sd5GhHejn2W9+HlfXy3kQg9jstX/twsARY3AgrnyQ\n+yQ2XPOVkMqQ0+FjgGTtz4qKaLxbAddjie2HFA5aJ88pS8MGBeS2AwrlNMsyDVXl\ncQOWYGpMp6sxvvuDroRfxg==\nPrivate-MAC: 084bc537318a4c44fbb728e5e6a53b60f9225806541f5fd86ccc13f78c15c1bf\n",
            },
        },
    },
}
