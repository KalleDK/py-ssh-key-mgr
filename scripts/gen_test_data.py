import ast
import contextlib
import dataclasses
import enum
import keyword
import pathlib
from ast import ImportFrom, Module, alias
from hashlib import sha256
from types import FunctionType, MethodType
from typing import Any, NewType, TypedDict, cast
from unittest.mock import patch

import ssh_proto_types as spt
import typer
from rich.console import Console

import ssh_key_mgr
import ssh_key_mgr.encryption
from ssh_key_mgr import putty
from ssh_key_mgr.encryption import (
    IV,
    ArgonID,
    CipherKey,
    MemoryCost,
    Parallelism,
    Salt,
    SecretBytes,
    TimeCost,
)
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
from ssh_key_mgr.putty.encryption import aes, argon
from ssh_key_mgr.putty.encryption.enc_aes256_cbc_argon2 import Encryption_AES256_CBC
from ssh_key_mgr.putty.encryption.enc_none import Encryption_NONE
from ssh_key_mgr.putty.keys import PuttyKeyPair

# region Unparse

app = typer.Typer()
console = Console()


@dataclasses.dataclass
class Parser:
    module: Module
    imported_names: list[str] = dataclasses.field(default_factory=list[str])

    def __post_init__(self):
        for node in self.module.body:
            if isinstance(node, ImportFrom):
                for alias in node.names:
                    self.imported_names.append(alias.asname or alias.name)

    def import_type(self, typ: type) -> type:
        if typ.__name__ not in self.imported_names and not keyword.iskeyword(typ.__name__):
            self.module.body.insert(
                0,
                ImportFrom(
                    module=typ.__module__,
                    names=[alias(name=typ.__name__, asname=None)],
                    level=0,
                ),
            )
            self.imported_names.append(typ.__name__)
        return typ

    def unparse_secretkey(self, obj: Any) -> ast.Call:
        if not isinstance(obj, SecretBytes):
            raise TypeError("expected secret key instance, got %r" % obj)

        value = obj.get_secret_value()
        return ast.Call(
            func=ast.Name(id=type(obj).__name__, ctx=ast.Load()),
            args=[self.unparse(value)],
            keywords=[],
        )

    def unparse_newtype(self, value: Any, typ: type) -> ast.Call:
        if not isinstance(typ, NewType):
            raise TypeError("expected NewType, got %r" % typ)
        self.import_type(typ)

        return ast.Call(
            func=ast.Name(id=typ.__name__, ctx=ast.Load()),
            args=[self.unparse(value)],
            keywords=[],
        )

    def unparse_dataclass(self, obj: Any) -> ast.Call:
        if not dataclasses.is_dataclass(obj):
            raise TypeError("expected dataclass instance, got %r" % obj)

        if type(obj).__name__ not in self.imported_names and not keyword.iskeyword(type(obj).__name__):
            self.module.body.insert(
                0,
                ImportFrom(
                    module=type(obj).__module__,
                    names=[alias(name=type(obj).__name__, asname=None)],
                    level=0,
                ),
            )
            self.imported_names.append(type(obj).__name__)

        return ast.Call(
            func=ast.Name(id=type(obj).__name__, ctx=ast.Load()),
            args=[],
            keywords=[
                ast.keyword(
                    arg=field.name,
                    value=self.unparse(getattr(obj, field.name), field.type),
                )
                for field in dataclasses.fields(obj)
            ],
        )

    def unparse_enum(self, obj: Any) -> ast.Attribute:
        if not isinstance(obj, enum.Enum):
            raise TypeError("expected enum instance, got %r" % obj)
        if type(obj).__name__ not in self.imported_names and not keyword.iskeyword(type(obj).__name__):
            self.module.body.insert(
                0,
                ImportFrom(
                    module=type(obj).__module__,
                    names=[alias(name=type(obj).__name__, asname=None)],
                    level=0,
                ),
            )
            self.imported_names.append(type(obj).__name__)
        return ast.Attribute(
            value=ast.Name(id=type(obj).__name__, ctx=ast.Load()),
            attr=obj.name,
            ctx=ast.Load(),
        )

    def unparse_typed_dict(self, typ: type) -> ast.ClassDef:
        if not hasattr(typ, "__required_keys__"):
            raise TypeError("expected TypedDict type, got %r" % typ)
        return ast.ClassDef(
            name=typ.__name__,
            bases=[ast.Name(id="TypedDict", ctx=ast.Load())],
            keywords=[],
            body=[
                ast.AnnAssign(
                    target=ast.Name(id=key, ctx=ast.Store()),
                    annotation=ast.Name(id=self.import_type(typ).__name__, ctx=ast.Load()),
                    value=None,
                    simple=1,
                )
                for key, typ in typ.__annotations__.items()
            ],
            decorator_list=[],
        )

    def unparse_class(self, obj: type) -> ast.ClassDef:
        if hasattr(obj, "__required_keys__"):
            return self.unparse_typed_dict(obj)
        raise TypeError("expected class type, got %r" % obj)

    def unparse(self, obj: Any, typ: type[Any] | str | None = None) -> ast.expr:
        if isinstance(typ, NewType):
            _type = cast(type, typ)
            return self.unparse_newtype(obj, _type)
        if isinstance(obj, enum.Enum):
            return self.unparse_enum(obj)
        if isinstance(obj, SecretBytes):
            return self.unparse_secretkey(obj)
        if isinstance(obj, list):
            _obj = cast(list[Any], obj)
            return ast.List(
                elts=[self.unparse(item) for item in _obj],
                ctx=ast.Load(),
            )
        if isinstance(obj, dict):
            _obj = cast(dict[Any, Any], obj)
            return ast.Dict(
                keys=[self.unparse(key) for key in _obj.keys()],
                values=[self.unparse(value) for value in _obj.values()],
            )
        if dataclasses.is_dataclass(obj):
            return self.unparse_dataclass(obj)

        if isinstance(obj, bytes):
            return ast.Call(
                func=ast.Attribute(value=ast.Name(id="bytes", ctx=ast.Load()), attr="fromhex", ctx=ast.Load()),
                args=[ast.Constant(value=obj.hex())],
                keywords=[],
            )
        if isinstance(obj, (str, int, float, bool, type(None))):
            return ast.Constant(value=obj)
        raise TypeError(f"Unsupported type: {type(obj)}")

    def assign(self, name: str, value: Any) -> ast.Assign:
        return ast.Assign(
            targets=[ast.Name(id=name, ctx=ast.Store())],
            value=self.unparse(value),
            lineno=0,
            type_comment=None,
        )

    def reassign(self, name: str | Any, value: Any = None) -> None:
        if value is None:
            value = name
            name = value.__name__
        for node in self.module.body:
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
                node.value = self.unparse(value)
                return
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
                node.value = self.unparse(value)
                return
            if isinstance(node, ast.ClassDef) and node.name == name:
                current = [
                    n.target.id for n in node.body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
                ]
                new_dict: ast.ClassDef = self.unparse_class(value)
                new_body = new_dict.body
                target = [
                    n.target.id for n in new_body if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)
                ]
                exists = set(current) & set(target)
                missing = set(target) - set(current)

                body: list[ast.stmt] = []
                for n in node.body:
                    if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id in exists:
                        body.append(n)
                for n in new_body:
                    if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.target.id in missing:
                        body.append(n)

                node.body = body
                return
        raise ValueError(f"Variable {name} not found in the module")


# endregion


#  region Seed Data


DATA = {
    "ED25519": KeyPairEd25519(
        comment="RFC8032 7.1 Test Vector 1",
        private=PrivateKeyEd25519(
            value=b"\x9d\x61\xb1\x9d\xef\xfdZ`\xba\x84J\xf4\x92\xec,\xc4DI\xc5i{2i\x19p;\xac\x03\x1c\xae\x7f`"
        ),
        public=PublicKeyEd25519(
            value=b"\xd7Z\x98\x01\x82\xb1\n\xb7\xd5K\xfe\xd3\xc9d\x07:\x0e\xe1r\xf3\xda\xa6#%\xaf\x02\x1ah\xf7\x07Q\x1a"
        ),
    ),
    "ED448": KeyPairEd448(
        comment="RFC8032 7.4 Test Vector 1",
        private=PrivateKeyEd448(
            value=b"l\x82\xa5b\xcb\x80\x8d\x10\xd62\xbe\x89\xc8Q>\xbfl\x92\x9f4\xdd\xfa\x8c\x9fc\xc9\x96\x0e\xf6\xe3H\xa3R\x8c\x8a?\xcc/\x04N9\xa3\xfc[\x94I/\x8f\x03.uI\xa2\x00\x98\xf9["
        ),
        public=PublicKeyEd448(
            value=b"_\xd7D\x9bY\xb4a\xfd,\xe7\x87\xecaj\xd4j\x1d\xa14$\x85\xa7\x0e\x1f\x8a\x0e\xa7]\x80\xe9gx\xed\xf1$v\x9bF\xc7\x06\x1b\xd6x=\xf1\xe5\x0fl\xd1\xfa\x1a\xbe\xaf\xe8%a\x80"
        ),
    ),
    "RSA_1024": KeyPairRSA(
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
    ),
}


# endregion


# region Randomness Control


def fake_randbytes(n: int) -> bytes:
    return bytes(range(1, n + 1))


def fake_gen_salt(size: int) -> Salt:
    return Salt(fake_randbytes(size))


def fake_gen_padding(size: int, block_size: int) -> bytes:
    padding = (block_size - size % block_size) % block_size  # padding
    if padding > 0:
        return fake_randbytes(padding)
    return b""


def name(o: FunctionType | MethodType) -> str:
    return o.__module__ + "." + o.__name__


@contextlib.contextmanager
def no_randomness():
    with patch(name(ssh_key_mgr.encryption.randbytes), wraps=fake_randbytes):
        yield


# endregion


def create_aes_test_params():
    result: dict[str, Any] = {}
    for i in range(2):
        hash_str = f"hash_{i + 1}"
        hash_bytes1 = sha256(hash_str.upper().encode()).digest()
        hash_bytes2 = sha256(hash_str.lower().encode()).digest()
        cipher_key = CipherKey(hash_bytes1[:32])
        iv = IV(hash_bytes2[:16])
        decrypted = b"decrypted_" + bytes(str(i + 1), "ascii")
        decrypted = decrypted + fake_gen_padding(len(decrypted), 16)
        result[f"TestVector_{i + 1}"] = {
            "CipherKey": cipher_key,
            "IV": iv,
            "Decrypted": decrypted,
            "Encrypted": aes.encrypt(decrypted, cipher_key, iv),
        }
    return result


def create_argon_test_params(hash_nr: int = 3):
    result: dict[str, Any] = {}
    for i in range(hash_nr):
        hash_length = 16 + i * 8
        salt = fake_gen_salt(16)
        params = argon.Argon2Params(
            type=ArgonID.ID,
            memory_cost=MemoryCost(8192),
            time_cost=TimeCost(21),
            parallelism=Parallelism(1),
            salt=salt,
        )
        passphrase = SecretBytes(b"passphrase_" + bytes(str(i), "ascii"))

        hash = argon.hash_passphrase(params, hash_length, passphrase)  # to verify it works
        result[f"TestVector_{hash_length}"] = {
            "Params": params,
            "Passphrase": passphrase,
            "Hash": hash,
            "HashLength": hash_length,
        }
    return result


def putty_public_key_wires():
    result: dict[str, bytes] = {}
    for name, keys in DATA.items():
        result[name] = spt.marshal(putty.from_general_pair(keys).public)
    return result


def putty_private_key_wires():
    result: dict[str, bytes] = {}
    for name, keys in DATA.items():
        result[name] = spt.marshal(putty.from_general_pair(keys).private)
    return result


def putty_public_keys():
    result: dict[str, putty.PuttyPublicKey] = {}
    for name, keys in DATA.items():
        result[name] = putty.from_general_pair(keys).public
    return result


class PuttyKeyEncryptionDict(TypedDict):
    Params: putty.Encryption
    Passphrase: SecretBytes | None
    FileObj: putty.PuttyFileV3
    File: str


class PuttyKeyTestDict(TypedDict):
    Obj: PuttyKeyPair
    PublicWire: bytes
    PrivateWire: bytes
    Encryptions: dict[str, PuttyKeyEncryptionDict]


def create_putty_encryption_test(params: putty.Encryption, keypair: PuttyKeyPair) -> PuttyKeyEncryptionDict:
    passphrase = None
    if params.require_passphrase:
        passphrase = SecretBytes(type(keypair).__name__.encode())
    file_obj = putty.PuttyFileV3.encrypt(keypair, params, passphrase)
    file = putty.dumps(file_obj)

    return {"Params": params, "Passphrase": passphrase, "FileObj": file_obj, "File": file.decode()}


def create_putty_key_test(key_name: str, keypair: KeyPair) -> PuttyKeyTestDict:
    _keypair = putty.from_general_pair(keypair)
    return {
        "Obj": _keypair,
        "PublicWire": spt.marshal(_keypair.public),
        "PrivateWire": spt.marshal(_keypair.private),
        "Encryptions": {
            "NONE": create_putty_encryption_test(Encryption_NONE(), _keypair),
            "AES256_CBC": create_putty_encryption_test(Encryption_AES256_CBC(), _keypair),
        },
    }


def create_putty_key_tests():
    result: dict[str, PuttyKeyTestDict] = {}
    with no_randomness():
        for name, keys in DATA.items():
            result[name] = create_putty_key_test(name, keys)
    return result


@app.command()
def main(path: pathlib.Path):
    parser = Parser(ast.parse(path.read_text()))
    for node in parser.module.body:
        console.print(node)
    parser.reassign("PUTTY_AES", create_aes_test_params())
    parser.reassign("PUTTY_ARGON", create_argon_test_params())
    parser.reassign("PUTTY_PUBLIC_KEY_WIRES", putty_public_key_wires())
    parser.reassign("PUTTY_PRIVATE_KEY_WIRES", putty_private_key_wires())
    parser.reassign("PUTTY_KEY_NAMES", list(DATA.keys()))
    parser.reassign("PUTTY_PUBLIC_KEYS", putty_public_keys())
    parser.reassign("PUTTY_KEY_TESTS", create_putty_key_tests())
    parser.reassign(PuttyKeyTestDict)

    unparsed = ast.unparse(parser.module)
    dst = path.with_name("data.py")
    dst.write_text(unparsed)
    console.print(f"Wrote to {dst}")


if __name__ == "__main__":
    app()
