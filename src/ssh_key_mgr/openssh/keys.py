import dataclasses
import inspect
from typing import ClassVar, Self

import ssh_proto_types as spt

# region Keys Base


class OpenSSHPublicKey(spt.Packet):
    key_type: ClassVar[str]


class OpenSSHPrivateKey(spt.Packet):
    key_type: ClassVar[str]

    @property
    def comment(self) -> str:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPair:
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


# endregion

# region Keys Ed25519

SSH_ED25519 = "ssh-ed25519"


class OpenSSHPublicKeyEd25519(OpenSSHPublicKey):
    key_type: ClassVar[str] = SSH_ED25519
    value: bytes


class OpenSSHPrivateKeyEd25519(OpenSSHPrivateKey):
    key_type: ClassVar[str] = SSH_ED25519
    public: bytes
    private: bytes
    _comment: str

    @classmethod
    def create(cls, private: bytes, public: bytes, comment: str) -> Self:
        if len(private) != 32:
            raise ValueError("Invalid private key length")
        if len(public) != 32:
            raise ValueError("Invalid public key length")

        return cls(
            public=public,
            private=private + public,
            _comment=comment,
        )

    @property
    def comment(self) -> str:
        return self._comment

    def __post_init__(self):
        self.validate()

    def validate(self):
        if len(self.public) != 32:
            raise ValueError("Invalid public key length")
        if len(self.private) != 64:
            raise ValueError("Invalid private key length")
        if self.private[32:] != self.public:
            raise ValueError("Private key does not end with public key")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairEd25519(OpenSSHKeyPair):
    key_type: ClassVar[str] = SSH_ED25519
    comment: str
    public: OpenSSHPublicKeyEd25519
    private: OpenSSHPrivateKeyEd25519


# endregion

# region Keys Ed448

SSH_ED448 = "ssh-ed448"


class OpenSSHPublicKeyEd448(OpenSSHPublicKey):
    key_type: ClassVar[str] = SSH_ED448
    value: bytes


class OpenSSHPrivateKeyEd448(OpenSSHPrivateKey):
    key_type: ClassVar[str] = SSH_ED448
    public: bytes
    private: bytes
    _comment: str

    @classmethod
    def create(cls, private: bytes, public: bytes, comment: str) -> Self:
        if len(private) != 57:
            raise ValueError("Invalid private key length")
        if len(public) != 57:
            raise ValueError("Invalid public key length")

        return cls(
            public=public,
            private=private + public,
            _comment=comment,
        )

    @property
    def comment(self) -> str:
        return self._comment

    def __post_init__(self):
        self.validate()

    def validate(self):
        if len(self.public) != 57:
            raise ValueError("Invalid public key length")
        if len(self.private) != 114:
            raise ValueError("Invalid private key length")
        if self.private[57:] != self.public:
            raise ValueError("Private key does not end with public key")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairEd448(OpenSSHKeyPair):
    key_type: ClassVar[str] = SSH_ED448
    comment: str
    public: OpenSSHPublicKeyEd448
    private: OpenSSHPrivateKeyEd448


# endregion

# region Keys RSA

SSH_RSA = "ssh-rsa"


class OpenSSHPublicKeyRSA(OpenSSHPublicKey):
    key_type: ClassVar[str] = SSH_RSA
    e: int
    n: int


class OpenSSHRSAPrivateKey(OpenSSHPrivateKey):
    key_type: ClassVar[str] = SSH_RSA
    n: int
    e: int
    d: int
    iqmp: int
    p: int
    q: int
    _comment: str

    @property
    def comment(self) -> str:
        return self._comment


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class OpenSSHKeyPairRSA(OpenSSHKeyPair):
    key_type: ClassVar[str] = SSH_RSA
    comment: str
    public: OpenSSHPublicKeyRSA
    private: OpenSSHRSAPrivateKey


# endregion
