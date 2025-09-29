import abc
import dataclasses
import inspect
from typing import Annotated, ClassVar, Self, override

import ssh_proto_types as spt

from ssh_key_mgr.keys import (
    SSH_ED448,
    SSH_ED25519,
    SSH_RSA,
    KeyPair,
    KeyPairEd448,
    KeyPairEd448Proto,
    KeyPairEd25519,
    KeyPairEd25519Proto,
    KeyPairProto,
    KeyPairRSA,
    KeyPairRSAProto,
    PrivateKeyEd448,
    PrivateKeyEd25519,
    PrivateKeyRSA,
    PublicKeyEd448,
    PublicKeyEd25519,
    PublicKeyRSA,
    SSHKeyType,
)

_KEYPAIR_REGISTRY: dict[str, type["PuttyKeyPair"]] = {}


# region Keys Base
class PuttyPublicKey(spt.Packet):
    key_type: ClassVar[str]


class PuttyPrivateKey(spt.Packet):
    key_type: ClassVar[Annotated[str, spt.exclude]]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyPair(KeyPairProto):
    __child_types: ClassVar[dict[str, type["PuttyKeyPair"]]] = {}
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

        _KEYPAIR_REGISTRY[cls.key_type] = cls
        cls.__private_types[cls.key_type] = annotations["private"]
        cls.__public_types[cls.key_type] = annotations["public"]
        cls.__child_types[cls.key_type] = cls

    @classmethod
    def unmarshal(
        cls, key_type: str, public_key: bytes | PuttyPublicKey, private_key: bytes | PuttyPrivateKey, comment: str
    ) -> "PuttyKeyPair":
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

    @abc.abstractmethod
    def to_general_pair(self) -> KeyPair:
        raise NotImplementedError


# endregion

# region Keys RSA


class PuttyPublicKeyRSA(PuttyPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    E: int
    N: int

    def to_general_key(self) -> PublicKeyRSA:
        return PublicKeyRSA(E=self.E, N=self.N)

    @classmethod
    def from_general_key(cls, key: PublicKeyRSA) -> Self:
        return cls(E=key.E, N=key.N)


class PuttyPrivateKeyRSA(PuttyPrivateKey):
    key_type: ClassVar[Annotated[SSHKeyType, spt.exclude]] = SSH_RSA
    D: int
    P: int
    Q: int
    Iqmp: int

    def to_general_key(self) -> PrivateKeyRSA:
        return PrivateKeyRSA(D=self.D, P=self.P, Q=self.Q, IQMP=self.Iqmp)

    @classmethod
    def from_general_key(cls, key: PrivateKeyRSA) -> Self:
        return cls(D=key.D, P=key.P, Q=key.Q, Iqmp=key.IQMP)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyPairRSA(PuttyKeyPair, KeyPairRSAProto):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    public: PuttyPublicKeyRSA
    private: PuttyPrivateKeyRSA

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairRSA) -> Self:
        return cls(
            public=PuttyPublicKeyRSA.from_general_key(keypair.public),
            private=PuttyPrivateKeyRSA.from_general_key(keypair.private),
            comment=keypair.comment,
        )

    @override
    def to_general_pair(self) -> KeyPairRSA:
        return KeyPairRSA(
            public=self.public.to_general_key(),
            private=self.private.to_general_key(),
            comment=self.comment,
        )


# endregion

# region Keys Ed25519


class PuttyPublicKeyEd25519(PuttyPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    key: bytes

    def to_general_key(self) -> PublicKeyEd25519:
        return PublicKeyEd25519(value=self.key)

    @classmethod
    def from_general_key(cls, key: PublicKeyEd25519) -> Self:
        return cls(key=key.value)


class PuttyPrivateKeyEd25519(PuttyPrivateKey):
    key_type: ClassVar[Annotated[SSHKeyType, spt.exclude]] = SSH_ED25519
    key: bytes

    def to_general_key(self) -> PrivateKeyEd25519:
        return PrivateKeyEd25519(value=self.key)

    @classmethod
    def from_general_key(cls, key: PrivateKeyEd25519) -> Self:
        return cls(key=key.value)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyEd25519(PuttyKeyPair, KeyPairEd25519Proto):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    public: PuttyPublicKeyEd25519
    private: PuttyPrivateKeyEd25519

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairEd25519) -> Self:
        return cls(
            public=PuttyPublicKeyEd25519.from_general_key(keypair.public),
            private=PuttyPrivateKeyEd25519.from_general_key(keypair.private),
            comment=keypair.comment,
        )

    def to_general_pair(self) -> KeyPairEd25519:
        return KeyPairEd25519(
            public=self.public.to_general_key(),
            private=self.private.to_general_key(),
            comment=self.comment,
        )


# endregion

# region Keys Ed448


class PuttyPublicKeyEd448(PuttyPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    key: bytes

    def to_general_key(self) -> PublicKeyEd448:
        return PublicKeyEd448(value=self.key)

    @classmethod
    def from_general_key(cls, key: PublicKeyEd448) -> Self:
        return cls(key=key.value)


class PuttyPrivateKeyEd448(PuttyPrivateKey):
    key_type: ClassVar[Annotated[SSHKeyType, spt.exclude]] = SSH_ED448
    key: bytes

    def to_general_key(self) -> PrivateKeyEd448:
        return PrivateKeyEd448(value=self.key)

    @classmethod
    def from_general_key(cls, key: PrivateKeyEd448) -> Self:
        return cls(key=key.value)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PuttyKeyEd448(PuttyKeyPair, KeyPairEd448Proto):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    public: PuttyPublicKeyEd448
    private: PuttyPrivateKeyEd448

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairEd448) -> Self:
        return cls(
            public=PuttyPublicKeyEd448.from_general_key(keypair.public),
            private=PuttyPrivateKeyEd448.from_general_key(keypair.private),
            comment=keypair.comment,
        )

    def to_general_pair(self) -> KeyPairEd448:
        return KeyPairEd448(
            public=self.public.to_general_key(),
            private=self.private.to_general_key(),
            comment=self.comment,
        )


# endregion

# endregion


def from_general_pair(keypair: KeyPair) -> PuttyKeyPair:
    if keypair.key_type not in _KEYPAIR_REGISTRY:
        raise ValueError(f"Unsupported key type {keypair.key_type}")
    return _KEYPAIR_REGISTRY[keypair.key_type].from_general_pair(keypair)  # type: ignore
