import dataclasses
from typing import ClassVar, NewType, Protocol, Self

SSHKeyType = NewType("SSHKeyType", str)

SSH_RSA = SSHKeyType("ssh-rsa")
SSH_ED25519 = SSHKeyType("ssh-ed25519")
SSH_ED448 = SSHKeyType("ssh-ed448")


# region Keys Base


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKey:
    key_type: ClassVar[str]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKey:
    key_type: ClassVar[str]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPair:
    key_type: ClassVar[str]
    comment: str
    public: PublicKey
    private: PrivateKey


class KeyPairProto(Protocol):
    def to_general_pair(self) -> KeyPair: ...


# endregion

# region Keys RSA


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyRSA(PublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    E: int
    N: int


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyRSA(PrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    D: int
    P: int
    Q: int
    IQMP: int


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairRSA(KeyPair):
    key_type: ClassVar[SSHKeyType] = SSH_RSA
    comment: str
    public: PublicKeyRSA
    private: PrivateKeyRSA


class KeyPairRSAProto(KeyPairProto, Protocol):
    @classmethod
    def from_general_pair(cls, keypair: KeyPairRSA) -> Self: ...

    def to_general_pair(self) -> KeyPairRSA: ...


# endregion

# region Keys Ed25519

SSH_ED25519_PUBLIC_KEY_LENGTH = 32
SSH_ED25519_PRIVATE_KEY_LENGTH = 32


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyEd25519(PublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    value: bytes

    def __post_init__(self):
        if len(self.value) != SSH_ED25519_PUBLIC_KEY_LENGTH:
            raise ValueError(
                f"Invalid public key length got {len(self.value)} expected {SSH_ED25519_PUBLIC_KEY_LENGTH}"
            )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyEd25519(PrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    value: bytes

    def __post_init__(self):
        if len(self.value) != SSH_ED25519_PRIVATE_KEY_LENGTH:
            raise ValueError(
                f"Invalid private key length got {len(self.value)} expected {SSH_ED25519_PRIVATE_KEY_LENGTH}"
            )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairEd25519(KeyPair):
    key_type: ClassVar[SSHKeyType] = SSH_ED25519
    comment: str
    public: PublicKeyEd25519
    private: PrivateKeyEd25519


class KeyPairEd25519Proto(KeyPairProto, Protocol):
    @classmethod
    def from_general_pair(cls, keypair: KeyPairEd25519) -> Self: ...

    def to_general_pair(self) -> KeyPairEd25519: ...


# endregion

# region Keys Ed448

SSH_ED448_PUBLIC_KEY_LENGTH = 57
SSH_ED448_PRIVATE_KEY_LENGTH = 57


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyEd448(PublicKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    value: bytes

    def __post_init__(self):
        if len(self.value) != SSH_ED448_PUBLIC_KEY_LENGTH:
            raise ValueError(f"Invalid public key length got {len(self.value)} expected {SSH_ED448_PUBLIC_KEY_LENGTH}")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyEd448(PrivateKey):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    value: bytes

    def __post_init__(self):
        if len(self.value) != SSH_ED448_PRIVATE_KEY_LENGTH:
            raise ValueError(
                f"Invalid private key length got {len(self.value)} expected {SSH_ED448_PRIVATE_KEY_LENGTH}"
            )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairEd448(KeyPair):
    key_type: ClassVar[SSHKeyType] = SSH_ED448
    comment: str
    public: PublicKeyEd448
    private: PrivateKeyEd448


class KeyPairEd448Proto(KeyPairProto, Protocol):
    @classmethod
    def from_general_pair(cls, keypair: KeyPairEd448) -> Self: ...

    def to_general_pair(self) -> KeyPairEd448: ...


# endregion
