import contextlib
import dataclasses
import pathlib
import sys
import typing
from hashlib import sha256
from typing import Annotated, Any
from unittest.mock import patch

import typer
import yaml
from yaml import ScalarNode

from ssh_key_mgr import openssh, putty
from ssh_key_mgr.keys import (
    KeyPair,
    KeyPairEd448,
    KeyPairEd25519,
    KeyPairRSA,
    PrivateKeyEd448,
    PrivateKeyEd25519,
    PrivateKeyRSA,
    PublicKeyEd448,
    PublicKeyEd25519,
    PublicKeyRSA,
)
from ssh_key_mgr.putty import encryption, ppk
from ssh_key_mgr.putty.encryption import SecretBytes, argon

app = typer.Typer(help="Generate keys and YAML data for testing.")

PARAMS_TYPES = {
    "NONE": (putty.Encryption_NONE, putty.Encryption_NONE_Params),
    "AES256_CBC": (putty.Encryption_AES256_CBC, putty.Encryption_AES256_CBC_Params),
}

# region Randomness Control


def fake_gen_salt(size: int) -> argon.Salt:
    return argon.Salt(bytes(range(1, size + 1)))


def fake_gen_padding(size: int, block_size: int = 16) -> bytes:
    pad_len = (block_size - (size % block_size)) % block_size
    return bytes(range(1, pad_len + 1))


def fake_uint32() -> int:
    return 1234567890


@contextlib.contextmanager
def no_randomness():
    with (
        patch(
            "ssh_key_mgr.putty.encryption.gen_salt",
            wraps=fake_gen_salt,
        ),
        patch(
            "ssh_key_mgr.putty.encryption.aes.gen_padding",
            wraps=fake_gen_padding,
        ),
        patch(
            "ssh_key_mgr.openssh.encryption.gen_random_uint32",
            wraps=fake_uint32,
        ),
        patch(
            "ssh_key_mgr.openssh.encryption.gen_salt",
            wraps=fake_gen_salt,
        ),
    ):
        yield


# endregion


def create_aes_test_params():
    result: dict[str, Any] = {}
    for i in range(2):
        hash_str = f"hash_{i + 1}"
        hash_bytes1 = sha256(hash_str.upper().encode()).digest()
        hash_bytes2 = sha256(hash_str.lower().encode()).digest()
        cipher_key = encryption.CipherKey(hash_bytes1[:32])
        iv = encryption.IV(hash_bytes2[:16])
        decrypted = b"decrypted_" + bytes(str(i + 1), "ascii")
        decrypted = decrypted + fake_gen_padding(len(decrypted), 16)
        result[f"TestVector_{i + 1}"] = {
            "CipherKey": f"CipherKey({repr(cipher_key.get_secret_value())})",
            "IV": f"IV({repr(iv.get_secret_value())})",
            "Decrypted": repr(decrypted),
            "Encrypted": repr(encryption.aes.encrypt(decrypted, cipher_key, iv)),
        }
    return result


def create_argon_test_params(hash_nr: int = 3):
    result: dict[str, Any] = {}
    for i in range(hash_nr):
        hash_length = 16 + i * 8
        salt = fake_gen_salt(16)
        params = argon.Argon2Params(
            type=argon.ArgonID.ID,
            memory_cost=argon.MemoryCost(8192),
            time_cost=argon.TimeCost(21),
            parallelism=argon.Parallelism(1),
            salt=salt,
        )
        passphrase = SecretBytes(b"passphrase_" + bytes(str(i), "ascii"))

        hash = argon.hash_passphrase(params, hash_length, passphrase)  # to verify it works
        result[f"TestVector_{hash_length}"] = {
            "Params": {"Salt": "Salt(" + repr(salt) + ")"},
            "Passphrase": f'SecretBytes(b"passphrase_{i}")',
            "Hash": repr(hash),
            "HashLength": hash_length,
        }
    return result


def create_putty(path: pathlib.Path, encryption: putty.Encryption, key: putty.PuttyKey, passphrase: SecretBytes | None):
    enc_params = encryption.generate_params()
    decrypted = enc_params.add_padding(bytes(key.private))
    encrypted, mackey = enc_params.encrypt(decrypted, passphrase)
    public_wire = bytes(key.public)
    mac = putty.Mac.generate(
        putty.MacData(
            comment=key.comment,
            algorithm=key.key_type,
            encryption=enc_params.encryption_type,
            public_wire=public_wire,
            private_padded_wire=decrypted,
        ),
        key=mackey,
    )
    ppk_file = ppk.marshal(
        putty.PuttyFileV3(
            key_type=key.key_type,
            comment=key.comment,
            decryption_params=enc_params,
            public_lines=public_wire,
            private_lines=encrypted,
            mac=mac,
        )
    )
    with path.open("wb") as f:
        f.write(ppk_file)
    return {
        "Passphrase": show_pass(passphrase),
        "Encrypted": repr(encrypted),
        "Decrypted": repr(decrypted),
        "MacKey": "MacKey(" + repr(mackey.get_secret_value()) + ")",
        "Mac": repr(mac),
        "DecryptParams": get_data_fields(enc_params),
        "EncryptParams": get_data_fields(encryption),
        "PPK": ppk_file.decode(),
    }


def get_data_value(value: Any):
    fields = get_data_fields(value)
    field_str = ", ".join(f"{k}={v}" for k, v in fields.items())
    return value.__class__.__name__ + "(" + field_str + ")"


def get_data_fields(obj: Any) -> dict[str, Any]:
    pub_data: dict[str, Any] = {}
    for field in dataclasses.fields(obj):
        value = getattr(obj, field.name)
        if dataclasses.is_dataclass(value):
            value = get_data_value(value)
        elif isinstance(field.type, typing.NewType):
            cls = str(field.type).split(".")[-1]
            value = f"{cls}({value})"
        elif isinstance(value, argon.ArgonID):
            value = f"ArgonID.{value.name}"
        elif isinstance(value, bytes):
            value = repr(value)
        pub_data[field.name] = value
    return pub_data


def show_pass(passphrase: SecretBytes | None) -> str:
    if passphrase is None:
        return "None"
    return f"SecretBytes({repr(passphrase.get_secret_value())})"


def create_key(
    path: pathlib.Path, name: str, key: KeyPair, aes256_cbc: putty.Encryption_AES256_CBC, passphrase: SecretBytes
):
    putty_key = key.to_putty()
    openssh_key = key.to_openssh()

    openssh_none = openssh.encode_file(
        openssh.EncryptedPrivateFile.encrypt(openssh_key, openssh.EncryptionParamsNone(), None)
    )
    openssh_aes256_ctr = openssh.encode_file(
        openssh.EncryptedPrivateFile.encrypt(openssh_key, openssh.EncryptionParamsAes256(), passphrase)
    )
    with (path / (name + "_none")).with_suffix(".pem").open("wb") as f:
        f.write(openssh_none)
    with (path / (name + "_aes256_ctr")).with_suffix(".pem").open("wb") as f:
        f.write(openssh_aes256_ctr)

    return {
        "Name": name,
        "Comment": key.comment,
        "PuttyKeyType": putty_key.__class__.__name__[len("PuttyKey") :],
        "PublicWire": repr(bytes(putty_key.public)),
        "PrivateWire": repr(bytes(putty_key.private)),
        "Data": {
            "Public": get_data_fields(putty_key.public),
            "Private": get_data_fields(putty_key.private),
        },
        "Putty": {
            "NONE": create_putty(
                (path / (name + "_none")).with_suffix(".ppk"), putty.Encryption_NONE(), putty_key, None
            ),
            "AES256_CBC": create_putty(
                (path / (name + "_aes256_cbc")).with_suffix(".ppk"), aes256_cbc, putty_key, passphrase
            ),
        },
        "OpenSSH": {
            "NONE": {"PEM": openssh_none.decode()},
            "AES256_CTR": {"PEM": openssh_aes256_ctr.decode()},
        },
    }


# region Generate Test Keys


def create_ed25519():
    return "SSH_ED25519", KeyPairEd25519(
        comment="RFC8032 7.1 Test Vector 1",
        private=PrivateKeyEd25519(
            private=b"\x9d\x61\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`"
        ),
        public=PublicKeyEd25519(
            value=b"\xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a"
        ),
    )


def create_ed448():
    return "SSH_ED448", KeyPairEd448(
        comment="RFC8032 7.4 Test Vector 1",
        private=PrivateKeyEd448(
            private=bytes.fromhex(
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
            )
        ),
        public=PublicKeyEd448(
            value=bytes.fromhex(
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
            )
        ),
    )


def create_rsa_1024():
    return "SSH_RSA_1024", KeyPairRSA(
        comment="testRSA1024",
        public=PublicKeyRSA(
            E=65537,
            N=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
        ),
        private=PrivateKeyRSA(
            D=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
            P=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
            Q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
            IQMP=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
        ),
    )


# endregion


def str_presenter(dumper: yaml.representer.SafeRepresenter, data: str) -> ScalarNode:
    if len(data.splitlines()) > 1:  # check for multiline string
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")  # pyright: ignore[reportUnknownMemberType]
    # if len(data) > 70:  # check for long string
    #    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return dumper.represent_scalar(tag="tag:yaml.org,2002:str", value=data)  # pyright: ignore[reportUnknownMemberType]


yaml.add_representer(str, str_presenter)
yaml.representer.SafeRepresenter.add_representer(str, str_presenter)


@app.command()
def main(out: Annotated[pathlib.Path, typer.Option()] = pathlib.Path("./keys")) -> None:
    with no_randomness():
        path = out
        path.mkdir(parents=True, exist_ok=True)
        typer.echo("Generating keys and YAML data...", err=True)
        name_1, key_1 = create_ed25519()

        name_2, key_2 = create_rsa_1024()

        name_3, key_3 = create_ed448()

        aes256_cbc = putty.Encryption_AES256_CBC()
        data: dict[str, Any] = {
            "AES": create_aes_test_params(),
            "Argon": create_argon_test_params(),
            "Passphrase": {
                "Correct": {"AES256_CBC": 'SecretBytes(b"correct horse battery staple")', "NONE": "None"},
                "Incorrect": {"AES256_CBC": 'SecretBytes(b"Tr0ub4dor&3")', "NONE": 'SecretBytes(b"wrong")'},
                "Invalid": {"AES256_CBC": "None", "NONE": 'SecretBytes(b"invalid")'},
            },
            "Keys": {
                name_1: create_key(path, name_1, key_1, aes256_cbc, SecretBytes(b"test1")),
                name_2: create_key(path, name_2, key_2, aes256_cbc, SecretBytes(b"test2")),
                name_3: create_key(path, name_3, key_3, aes256_cbc, SecretBytes(b"test3")),
            },
            "Putty": {
                "Encryption": [
                    "AES256_CBC",
                    "NONE",
                ],
                "KeyType": {
                    "Ed25519": {"Type": "ssh-ed25519"},
                    "RSA": {"Type": "ssh-rsa"},
                    "Ed448": {"Type": "ssh-ed448"},
                },
            },
        }

        yaml.safe_dump(data, sys.stdout, sort_keys=False, width=70)


if __name__ == "__main__":
    app()
