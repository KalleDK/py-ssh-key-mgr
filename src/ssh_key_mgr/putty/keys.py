import dataclasses
import inspect
from typing import Annotated, ClassVar

import ssh_proto_types as spt


# region Keys Base
class PuttyPublicKey(spt.Packet):
    key_type: ClassVar[str]


class PuttyPrivateKey(spt.Packet):
    key_type: ClassVar[Annotated[str, spt.exclude]]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKey:
    __child_types: ClassVar[dict[str, type["PuttyKey"]]] = {}
    __private_types: ClassVar[dict[str, type["PuttyPrivateKey"]]] = {}
    __public_types: ClassVar[dict[str, type["PuttyPublicKey"]]] = {}

    key_type: ClassVar[str]
    public: PuttyPublicKey
    private: PuttyPrivateKey
    comment: str

    def __init_subclass__(cls) -> None:
        annotations = inspect.get_annotations(cls)

        if not issubclass(annotations["private"], PuttyPrivateKey):
            raise TypeError("private must be a subclass of PuttyPrivateKey")

        if not issubclass(annotations["public"], PuttyPublicKey):
            raise TypeError("public must be a subclass of PuttyPublicKey")

        cls.__private_types[cls.key_type] = annotations["private"]
        cls.__public_types[cls.key_type] = annotations["public"]
        cls.__child_types[cls.key_type] = cls

    @classmethod
    def unmarshal(
        cls, key_type: str, public_key: bytes | PuttyPublicKey, private_key: bytes | PuttyPrivateKey, comment: str
    ) -> "PuttyKey":
        if key_type not in cls.__child_types:
            raise ValueError(f"Unsupported key type {key_type}")

        public_key_type = cls.__public_types[key_type]
        match public_key:
            case bytes():
                public = spt.unmarshal(public_key_type, public_key)
            case PuttyPublicKey():
                if not isinstance(public_key, public_key_type):
                    raise TypeError(f"public_key must be of type {public_key_type.__name__}")
                public = public_key

        private_key_type = cls.__private_types[key_type]
        match private_key:
            case bytes():
                private = spt.unmarshal(cls.__private_types[key_type], private_key, {"key_type": key_type})
            case PuttyPrivateKey():
                if not isinstance(private_key, private_key_type):
                    raise TypeError(f"private_key must be of type {private_key_type.__name__}")
                private = private_key
        return cls.__child_types[key_type](public=public, private=private, comment=comment)


# endregion

# region Keys RSA

RSA_NAME = "ssh-rsa"


class PuttyPublicKeyRSA(PuttyPublicKey):
    key_type: ClassVar[str] = RSA_NAME
    E: int
    N: int


class PuttyPrivateKeyRSA(PuttyPrivateKey):
    key_type: ClassVar[Annotated[str, spt.exclude]] = RSA_NAME
    D: int
    P: int
    Q: int
    Iqmp: int


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyRSA(PuttyKey):
    key_type: ClassVar[str] = RSA_NAME
    public: PuttyPublicKeyRSA
    private: PuttyPrivateKeyRSA


# endregion

# region Keys Ed25519

ED25519_NAME = "ssh-ed25519"


class PuttyPublicKeyEd25519(PuttyPublicKey):
    key_type: ClassVar[str] = ED25519_NAME
    key: bytes


class PuttyPrivateKeyEd25519(PuttyPrivateKey):
    key_type: ClassVar[Annotated[str, spt.exclude]] = ED25519_NAME
    key: bytes


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyEd25519(PuttyKey):
    key_type: ClassVar[str] = ED25519_NAME
    public: PuttyPublicKeyEd25519
    private: PuttyPrivateKeyEd25519


# endregion


# region Keys Ed448

ED448_NAME = "ssh-ed448"


class PuttyPublicKeyEd448(PuttyPublicKey):
    key_type: ClassVar[str] = ED448_NAME
    key: bytes


class PuttyPrivateKeyEd448(PuttyPrivateKey):
    key_type: ClassVar[Annotated[str, spt.exclude]] = ED448_NAME
    key: bytes


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyEd448(PuttyKey):
    key_type: ClassVar[str] = ED448_NAME
    public: PuttyPublicKeyEd448
    private: PuttyPrivateKeyEd448


# endregion

# endregion
