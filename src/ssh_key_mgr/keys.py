import abc
import dataclasses
from typing import ClassVar, Self, cast, override

from ssh_key_mgr.openssh.keys import (
    OpenSSHKeyPair,
    OpenSSHKeyPairEd448,
    OpenSSHKeyPairEd25519,
    OpenSSHKeyPairRSA,
    OpenSSHPrivateKeyEd448,
    OpenSSHPrivateKeyEd25519,
    OpenSSHPublicKeyEd448,
    OpenSSHPublicKeyEd25519,
    OpenSSHPublicKeyRSA,
    OpenSSHRSAPrivateKey,
)
from ssh_key_mgr.putty import (
    PuttyKey,
    PuttyKeyEd25519,
    PuttyKeyRSA,
    PuttyPrivateKeyEd25519,
    PuttyPrivateKeyRSA,
    PuttyPublicKeyEd25519,
    PuttyPublicKeyRSA,
)
from ssh_key_mgr.putty.keys import PuttyKeyEd448, PuttyPrivateKeyEd448, PuttyPublicKeyEd448

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

    @abc.abstractmethod
    def to_putty(self) -> PuttyKey:
        raise NotImplementedError

    @classmethod
    def from_putty(cls, key: PuttyKey) -> Self:
        match key:
            case PuttyKeyRSA():
                return cast(Self, KeyPairRSA.from_putty(key))
            case PuttyKeyEd25519():
                return cast(Self, KeyPairEd25519.from_putty(key))
            case _:
                raise ValueError(f"Unsupported key type: {key.key_type}")

    @abc.abstractmethod
    def to_openssh(self) -> OpenSSHKeyPair:
        raise NotImplementedError

    @classmethod
    def from_openssh(cls, keypair: OpenSSHKeyPair) -> Self:
        match keypair:
            case OpenSSHKeyPairRSA():
                return cast(Self, KeyPairRSA.from_openssh(keypair))
            case OpenSSHKeyPairEd25519():
                return cast(Self, KeyPairEd25519.from_openssh(keypair))
            case _:
                raise ValueError(f"Unsupported key type: {keypair.key_type}")


# endregion

# region Keys RSA

SSH_RSA = "ssh-rsa"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyRSA(PublicKey):
    key_type: ClassVar[str] = SSH_RSA
    E: int
    N: int

    @classmethod
    def from_putty(cls, key: PuttyPublicKeyRSA) -> Self:
        return cls(E=key.E, N=key.N)

    def to_putty(self) -> PuttyPublicKeyRSA:
        return PuttyPublicKeyRSA(E=self.E, N=self.N)

    @classmethod
    def from_openssh(cls, key: OpenSSHPublicKeyRSA) -> Self:
        return cls(E=key.e, N=key.n)

    def to_openssh(self) -> OpenSSHPublicKeyRSA:
        return OpenSSHPublicKeyRSA(e=self.E, n=self.N)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyRSA(PrivateKey):
    key_type: ClassVar[str] = SSH_RSA
    D: int
    P: int
    Q: int
    IQMP: int

    @classmethod
    def from_putty(cls, key: PuttyPrivateKeyRSA) -> Self:
        return cls(
            D=key.D,
            P=key.P,
            Q=key.Q,
            IQMP=key.Iqmp,
        )

    def to_putty(self) -> PuttyPrivateKeyRSA:
        return PuttyPrivateKeyRSA(
            D=self.D,
            P=self.P,
            Q=self.Q,
            Iqmp=self.IQMP,
        )

    @classmethod
    def from_openssh(cls, key: OpenSSHRSAPrivateKey) -> Self:
        return cls(D=key.d, P=key.p, Q=key.q, IQMP=key.iqmp)

    def to_openssh(self, public: PublicKeyRSA, comment: str) -> OpenSSHRSAPrivateKey:
        return OpenSSHRSAPrivateKey(
            n=public.N,
            e=public.E,
            d=self.D,
            p=self.P,
            q=self.Q,
            iqmp=self.IQMP,
            _comment=comment,
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairRSA(KeyPair):
    key_type: ClassVar[str] = SSH_RSA
    comment: str
    public: PublicKeyRSA
    private: PrivateKeyRSA

    @classmethod
    @override
    def from_putty(cls, key: PuttyKey) -> Self:
        if not isinstance(key, PuttyKeyRSA):
            raise ValueError(f"Invalid key type: {type(key)}")
        return cls(
            comment=key.comment,
            public=PublicKeyRSA.from_putty(key.public),
            private=PrivateKeyRSA.from_putty(key.private),
        )

    @override
    def to_putty(self) -> PuttyKey:
        return PuttyKeyRSA(
            comment=self.comment,
            public=self.public.to_putty(),
            private=self.private.to_putty(),
        )

    @classmethod
    @override
    def from_openssh(cls, keypair: OpenSSHKeyPair) -> Self:
        if not isinstance(keypair, OpenSSHKeyPairRSA):
            raise ValueError(f"Invalid key pair type: {type(keypair)}")
        return cls(
            comment=keypair.comment,
            public=PublicKeyRSA.from_openssh(keypair.public),
            private=PrivateKeyRSA.from_openssh(keypair.private),
        )

    @override
    def to_openssh(self) -> OpenSSHKeyPairRSA:
        return OpenSSHKeyPairRSA(
            comment=self.comment,
            public=self.public.to_openssh(),
            private=self.private.to_openssh(public=self.public, comment=self.comment),
        )


# endregion

# region Keys Ed25519

SSH_ED25519 = "ssh-ed25519"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyEd25519(PublicKey):
    key_type: ClassVar[str] = SSH_ED25519
    value: bytes

    def __post_init__(self):
        if len(self.value) != 32:
            raise ValueError("Invalid public key length")

    @classmethod
    def from_putty(cls, key: PuttyPublicKeyEd25519) -> Self:
        return cls(value=key.key)

    def to_putty(self) -> PuttyPublicKeyEd25519:
        return PuttyPublicKeyEd25519(key=self.value)

    @classmethod
    def from_openssh(cls, key: OpenSSHPublicKeyEd25519) -> Self:
        return cls(value=key.value)

    def to_openssh(self) -> OpenSSHPublicKeyEd25519:
        return OpenSSHPublicKeyEd25519(value=self.value)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyEd25519(PrivateKey):
    key_type: ClassVar[str] = SSH_ED25519
    private: bytes

    def __post_init__(self):
        if len(self.private) != 32:
            raise ValueError("Invalid private key length")

    @classmethod
    def from_putty(cls, key: PuttyPrivateKeyEd25519) -> Self:
        return cls(private=key.key)

    def to_putty(self) -> PuttyPrivateKeyEd25519:
        return PuttyPrivateKeyEd25519(key=self.private)

    @classmethod
    def from_openssh(cls, key: OpenSSHPrivateKeyEd25519) -> Self:
        return cls(
            private=key.private[:32],
        )

    def to_openssh(self, public: PublicKeyEd25519, comment: str) -> OpenSSHPrivateKeyEd25519:
        return OpenSSHPrivateKeyEd25519(
            public=public.value,
            private=self.private + public.value,
            _comment=comment,
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairEd25519(KeyPair):
    key_type: ClassVar[str] = SSH_ED25519
    comment: str
    public: PublicKeyEd25519
    private: PrivateKeyEd25519

    @classmethod
    @override
    def from_putty(cls, key: PuttyKey) -> Self:
        if not isinstance(key, PuttyKeyEd25519):
            raise ValueError(f"Invalid key type: {type(key)}")
        return cls(
            comment=key.comment,
            public=PublicKeyEd25519.from_putty(key.public),
            private=PrivateKeyEd25519.from_putty(key.private),
        )

    @override
    def to_putty(self) -> PuttyKey:
        return PuttyKeyEd25519(
            comment=self.comment,
            public=self.public.to_putty(),
            private=self.private.to_putty(),
        )

    @classmethod
    @override
    def from_openssh(cls, keypair: OpenSSHKeyPair) -> Self:
        if not isinstance(keypair, OpenSSHKeyPairEd25519):
            raise ValueError(f"Invalid key pair type: {type(keypair)}")
        return cls(
            comment=keypair.comment,
            public=PublicKeyEd25519(value=keypair.public.value),
            private=PrivateKeyEd25519(private=keypair.private.private),
        )

    @override
    def to_openssh(self) -> OpenSSHKeyPairEd25519:
        return OpenSSHKeyPairEd25519(
            comment=self.comment,
            public=self.public.to_openssh(),
            private=self.private.to_openssh(public=self.public, comment=self.comment),
        )


# endregion


# region Keys Ed448

SSH_ED448 = "ssh-ed448"


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PublicKeyEd448(PublicKey):
    key_type: ClassVar[str] = SSH_ED448
    value: bytes

    def __post_init__(self):
        if len(self.value) != 57:
            raise ValueError("Invalid public key length")

    @classmethod
    def from_putty(cls, key: PuttyPublicKeyEd448) -> Self:
        return cls(value=key.key)

    def to_putty(self) -> PuttyPublicKeyEd448:
        return PuttyPublicKeyEd448(key=self.value)

    @classmethod
    def from_openssh(cls, key: OpenSSHPublicKeyEd448) -> Self:
        return cls(value=key.value)

    def to_openssh(self) -> OpenSSHPublicKeyEd448:
        return OpenSSHPublicKeyEd448(value=self.value)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PrivateKeyEd448(PrivateKey):
    key_type: ClassVar[str] = SSH_ED448
    private: bytes

    def __post_init__(self):
        if len(self.private) != 57:
            raise ValueError("Invalid private key length")

    @classmethod
    def from_putty(cls, key: PuttyPrivateKeyEd448) -> Self:
        return cls(private=key.key)

    def to_putty(self) -> PuttyPrivateKeyEd448:
        return PuttyPrivateKeyEd448(key=self.private)

    @classmethod
    def from_openssh(cls, key: OpenSSHPrivateKeyEd448) -> Self:
        return cls(
            private=key.private[:57],
        )

    def to_openssh(self, public: PublicKeyEd448, comment: str) -> OpenSSHPrivateKeyEd448:
        return OpenSSHPrivateKeyEd448(
            public=public.value,
            private=self.private + public.value,
            _comment=comment,
        )


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class KeyPairEd448(KeyPair):
    key_type: ClassVar[str] = SSH_ED448
    comment: str
    public: PublicKeyEd448
    private: PrivateKeyEd448

    @classmethod
    @override
    def from_putty(cls, key: PuttyKey) -> Self:
        if not isinstance(key, PuttyKeyEd448):
            raise ValueError(f"Invalid key type: {type(key)}")
        return cls(
            comment=key.comment,
            public=PublicKeyEd448.from_putty(key.public),
            private=PrivateKeyEd448.from_putty(key.private),
        )

    @override
    def to_putty(self) -> PuttyKey:
        return PuttyKeyEd448(
            comment=self.comment,
            public=self.public.to_putty(),
            private=self.private.to_putty(),
        )

    @classmethod
    @override
    def from_openssh(cls, keypair: OpenSSHKeyPair) -> Self:
        if not isinstance(keypair, OpenSSHKeyPairEd448):
            raise ValueError(f"Invalid key pair type: {type(keypair)}")
        return cls(
            comment=keypair.comment,
            public=PublicKeyEd448(value=keypair.public.value),
            private=PrivateKeyEd448(private=keypair.private.private),
        )

    @override
    def to_openssh(self) -> OpenSSHKeyPairEd448:
        return OpenSSHKeyPairEd448(
            comment=self.comment,
            public=self.public.to_openssh(),
            private=self.private.to_openssh(public=self.public, comment=self.comment),
        )


# endregion
