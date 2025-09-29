import abc
import dataclasses
import inspect
from typing import ClassVar, Self, override

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

# region Keys Base


class OpenSSHPublicKey(spt.Packet):
    key_type: ClassVar[str]


class OpenSSHPrivateKey(spt.Packet):
    key_type: ClassVar[str]

    @property
    def comment(self) -> str:
        raise NotImplementedError


_KEYPAIR_REGISTRY: dict[str, type["OpenSSHKeyPair"]] = {}


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPair(KeyPairProto):
    __child_types: ClassVar[dict[str, type["OpenSSHKeyPair"]]] = {}
    __private_types: ClassVar[dict[str, type["OpenSSHPrivateKey"]]] = {}
    __public_types: ClassVar[dict[str, type["OpenSSHPublicKey"]]] = {}
    key_type: ClassVar[str]
    comment: str
    public: OpenSSHPublicKey
    private: OpenSSHPrivateKey

    def __init_subclass__(cls) -> None:
        annotations = inspect.get_annotations(cls)

        if not issubclass(annotations["private"], OpenSSHPrivateKey):
            raise TypeError("private must be a subclass of OpenSSHPrivateKey")

        if not issubclass(annotations["public"], OpenSSHPublicKey):
            raise TypeError("public must be a subclass of OpenSSHPublicKey")

        cls.__private_types[cls.key_type] = annotations["private"]
        cls.__public_types[cls.key_type] = annotations["public"]
        cls.__child_types[cls.key_type] = cls
        _KEYPAIR_REGISTRY[cls.key_type] = cls

    @classmethod
    def unmarshal(cls, public_key: OpenSSHPublicKey, private_key: OpenSSHPrivateKey) -> "OpenSSHKeyPair":
        if public_key.key_type != private_key.key_type:
            raise ValueError("Public and private key types do not match")
        key_type = public_key.key_type

        if key_type not in cls.__child_types:
            raise ValueError(f"Unsupported key type {key_type}")

        public_key_type = cls.__public_types[key_type]
        match public_key:
            case OpenSSHPublicKey():
                if not isinstance(public_key, public_key_type):
                    raise TypeError(f"public_key must be of type {public_key_type.__name__}")
                public = public_key

        private_key_type = cls.__private_types[key_type]
        match private_key:
            case OpenSSHPrivateKey():
                if not isinstance(private_key, private_key_type):
                    raise TypeError(f"private_key must be of type {private_key_type.__name__}")
                private = private_key
        return cls.__child_types[key_type](public=public, private=private, comment=private.comment)

    @abc.abstractmethod
    def to_general_pair(self) -> KeyPair:
        raise NotImplementedError


# endregion

# region Keys Ed25519


SSH_ED25519_PRIVATE_KEY_PART_LENGTH = 256 // 8
SSH_ED25519_PUBLIC_KEY_PART_LENGTH = 256 // 8
SSH_ED25519_PUBLIC_KEY_LENGTH = SSH_ED25519_PUBLIC_KEY_PART_LENGTH
SSH_ED25519_PRIVATE_KEY_LENGTH = SSH_ED25519_PRIVATE_KEY_PART_LENGTH + SSH_ED25519_PUBLIC_KEY_PART_LENGTH


class OpenSSHPublicKeyEd25519(OpenSSHPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    value: bytes

    @classmethod
    def from_general_key(cls, key: PublicKeyEd25519) -> Self:
        return cls(value=key.value)

    def to_general_key(self) -> PublicKeyEd25519:
        return PublicKeyEd25519(value=self.value)


class OpenSSHPrivateKeyEd25519(OpenSSHPrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    public: bytes
    private: bytes
    _comment: str

    @property
    def comment(self) -> str:
        return self._comment

    @property
    def private_key_part(self) -> bytes:
        return self.private[:SSH_ED25519_PRIVATE_KEY_PART_LENGTH]

    @property
    def public_key_part(self) -> bytes:
        return self.private[SSH_ED25519_PRIVATE_KEY_PART_LENGTH:]

    def __post_init__(self):
        if len(self.public) != SSH_ED25519_PUBLIC_KEY_LENGTH:
            raise ValueError("Invalid public key length")
        if len(self.private) != SSH_ED25519_PRIVATE_KEY_LENGTH:
            raise ValueError("Invalid private key length")
        if self.public_key_part != self.public:
            raise ValueError("Public key part of private key does not match public key")

    @classmethod
    def create(cls, private: bytes, public: bytes, comment: str) -> Self:
        if len(private) != SSH_ED25519_PRIVATE_KEY_PART_LENGTH:
            raise ValueError("Invalid private key length")
        if len(public) != SSH_ED25519_PUBLIC_KEY_PART_LENGTH:
            raise ValueError("Invalid public key length")

        return cls(
            public=public,
            private=private + public,
            _comment=comment,
        )

    @classmethod
    def from_general_key(cls, private: PrivateKeyEd25519, public: PublicKeyEd25519, comment: str) -> Self:
        return cls.create(private=private.value, public=public.value, comment=comment)

    def to_general_key(self) -> PrivateKeyEd25519:
        return PrivateKeyEd25519(value=self.private_key_part)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairEd25519(OpenSSHKeyPair, KeyPairEd25519Proto):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    comment: str
    public: OpenSSHPublicKeyEd25519
    private: OpenSSHPrivateKeyEd25519

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairEd25519) -> Self:
        return cls(
            public=OpenSSHPublicKeyEd25519.from_general_key(keypair.public),
            private=OpenSSHPrivateKeyEd25519.from_general_key(keypair.private, keypair.public, keypair.comment),
            comment=keypair.comment,
        )

    @override
    def to_general_pair(self) -> KeyPairEd25519:
        return KeyPairEd25519(
            public=self.public.to_general_key(),
            private=self.private.to_general_key(),
            comment=self.comment,
        )


# endregion

# region Keys Ed448

SSH_ED448_PRIVATE_KEY_PART_LENGTH = 456 // 8
SSH_ED448_PUBLIC_KEY_PART_LENGTH = 456 // 8
SSH_ED448_PUBLIC_KEY_LENGTH = SSH_ED448_PUBLIC_KEY_PART_LENGTH
SSH_ED448_PRIVATE_KEY_LENGTH = SSH_ED448_PRIVATE_KEY_PART_LENGTH + SSH_ED448_PUBLIC_KEY_PART_LENGTH


class OpenSSHPublicKeyEd448(OpenSSHPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    value: bytes

    @classmethod
    def from_general_key(cls, key: PublicKeyEd448) -> Self:
        return cls(value=key.value)

    def to_general_key(self) -> PublicKeyEd448:
        return PublicKeyEd448(value=self.value)


class OpenSSHPrivateKeyEd448(OpenSSHPrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    public: bytes
    private: bytes
    _comment: str

    @property
    def comment(self) -> str:
        return self._comment

    @property
    def private_key_part(self) -> bytes:
        return self.private[:SSH_ED448_PRIVATE_KEY_PART_LENGTH]

    @property
    def public_key_part(self) -> bytes:
        return self.private[SSH_ED448_PRIVATE_KEY_PART_LENGTH:]

    def __post_init__(self):
        if len(self.public) != SSH_ED448_PUBLIC_KEY_LENGTH:
            raise ValueError("Invalid public key length")
        if len(self.private) != SSH_ED448_PRIVATE_KEY_LENGTH:
            raise ValueError("Invalid private key length")
        if self.public_key_part != self.public:
            raise ValueError("Public key part of private key does not match public key")

    @classmethod
    def create(cls, private: bytes, public: bytes, comment: str) -> Self:
        if len(private) != SSH_ED448_PRIVATE_KEY_PART_LENGTH:
            raise ValueError("Invalid private key length")
        if len(public) != SSH_ED448_PUBLIC_KEY_PART_LENGTH:
            raise ValueError("Invalid public key length")

        return cls(
            public=public,
            private=private + public,
            _comment=comment,
        )

    @classmethod
    def from_general_key(cls, private: PrivateKeyEd448, public: PublicKeyEd448, comment: str) -> Self:
        return cls.create(private=private.value, public=public.value, comment=comment)

    def to_general_key(self) -> PrivateKeyEd448:
        return PrivateKeyEd448(value=self.private_key_part)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairEd448(OpenSSHKeyPair, KeyPairEd448Proto):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    comment: str
    public: OpenSSHPublicKeyEd448
    private: OpenSSHPrivateKeyEd448

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairEd448) -> Self:
        return cls(
            public=OpenSSHPublicKeyEd448.from_general_key(keypair.public),
            private=OpenSSHPrivateKeyEd448.from_general_key(keypair.private, keypair.public, keypair.comment),
            comment=keypair.comment,
        )

    @override
    def to_general_pair(self) -> KeyPairEd448:
        return KeyPairEd448(
            public=self.public.to_general_key(),
            private=self.private.to_general_key(),
            comment=self.comment,
        )


# endregion

# region Keys RSA


class OpenSSHPublicKeyRSA(OpenSSHPublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    e: int
    n: int

    def to_general_key(self) -> PublicKeyRSA:
        return PublicKeyRSA(E=self.e, N=self.n)

    @classmethod
    def from_general_key(cls, key: PublicKeyRSA) -> Self:
        return cls(e=key.E, n=key.N)


class OpenSSHRSAPrivateKey(OpenSSHPrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    _comment: str

    def to_general_key(self) -> PrivateKeyRSA:
        return PrivateKeyRSA(D=self.d, P=self.p, Q=self.q, IQMP=self.iqmp)

    @classmethod
    def from_general_key(cls, private: PrivateKeyRSA, public: PublicKeyRSA, comment: str) -> Self:
        return cls(n=public.N, e=public.E, d=private.D, iqmp=private.IQMP, p=private.P, q=private.Q, _comment=comment)

    @property
    def comment(self) -> str:
        return self._comment


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairRSA(OpenSSHKeyPair, KeyPairRSAProto):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    comment: str
    public: OpenSSHPublicKeyRSA
    private: OpenSSHRSAPrivateKey

    @classmethod
    @override
    def from_general_pair(cls, keypair: KeyPairRSA) -> Self:
        return cls(
            public=OpenSSHPublicKeyRSA.from_general_key(keypair.public),
            private=OpenSSHRSAPrivateKey.from_general_key(keypair.private, keypair.public, keypair.comment),
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


def from_general_pair(keypair: KeyPair) -> OpenSSHKeyPair:
    if keypair.key_type not in _KEYPAIR_REGISTRY:
        raise ValueError(f"Unsupported key type {keypair.key_type}")
    return _KEYPAIR_REGISTRY[keypair.key_type].from_general_pair(keypair)  # type: ignore
