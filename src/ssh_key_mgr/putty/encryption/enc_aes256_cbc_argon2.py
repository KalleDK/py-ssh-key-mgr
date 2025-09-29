import dataclasses
from typing import ClassVar, NamedTuple, Self, SupportsBytes, override

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
    gen_random_padding,
    gen_salt,
)
from ssh_key_mgr.putty import ppk
from ssh_key_mgr.putty.checksum import MacKey
from ssh_key_mgr.putty.encryption import aes, argon
from ssh_key_mgr.putty.encryption.base import DecryptionParams, Encryption, EncryptionParams
from ssh_key_mgr.putty.ppk.stream import HexField, IntField, StrField


class AESParams(NamedTuple):
    block_size: int
    cipher_key_length: int
    cipher_iv_length: int
    mac_key_length: int

    @property
    def hash_size(self) -> int:
        return self.cipher_key_length + self.cipher_iv_length + self.mac_key_length


def slice(data: bytes, size: int) -> tuple[bytes, bytes]:
    return data[:size], data[size:]


def derive_aes_key(
    argon_params: Argon2Params, aes_params: AESParams, passphrase: SecretBytes
) -> tuple[CipherKey, IV, MacKey]:
    key = argon.hash_passphrase(argon_params, aes_params.hash_size, passphrase)
    cipher_key, rest = slice(key, aes_params.cipher_key_length)
    iv, mac_key = slice(rest, aes_params.cipher_iv_length)
    return CipherKey(cipher_key), IV(iv), MacKey(mac_key)


def aes_decrypt(
    encrypted: EncryptedBytes, argon_params: argon.Argon2Params, aes_params: "AESParams", passphrase: SecretBytes
) -> tuple[bytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(argon_params, aes_params, passphrase)

    decrypted = aes.decrypt(encrypted, cipher_key, iv)

    return decrypted, mac_key


def aes_encrypt(
    decrypted: SupportsBytes, argon_params: argon.Argon2Params, aes_params: "AESParams", passphrase: SecretBytes
) -> tuple[EncryptedBytes, MacKey]:
    cipher_key, iv, mac_key = derive_aes_key(argon_params, aes_params, passphrase)

    encrypted = aes.encrypt(bytes(decrypted), cipher_key, iv)

    return encrypted, mac_key


def add_padding(data: bytes, block_size: int) -> bytes:
    return data + gen_random_padding(len(data), block_size=block_size)


ENCRYPTION_NAME = "aes256-cbc"

SALT_SIZE = 16
BLOCK_SIZE = 16
CIPHER_KEY_SIZE = 32
IV_SIZE = 16
MAC_KEY_SIZE = 32

AES_PARAMS = AESParams(
    block_size=BLOCK_SIZE,
    cipher_key_length=CIPHER_KEY_SIZE,
    cipher_iv_length=IV_SIZE,
    mac_key_length=MAC_KEY_SIZE,
)

REQUIRE_PASSPHRASE = True

DEFAULT_ARGON_TYPE = ArgonID.ID
DEFAULT_ARGON_MEMORY_COST = MemoryCost(8192)
DEFAULT_ARGON_TIME_COST = TimeCost(21)
DEFAULT_ARGON_PARALLELISM = Parallelism(1)


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Decryption_AES256_CBC_Params(DecryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME
    argon2_params: argon.Argon2Params

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @override
    @classmethod
    def unmarshal_ppk_part(cls, encryption_type: str, stream: ppk.StreamReader) -> Self:
        if encryption_type != cls.encryption_type:
            raise ValueError(f"Expected encryption type {cls.encryption_type}, got {encryption_type}")

        key_derivation = ArgonID(stream.read_named_str("Key-Derivation"))
        argon2_memory = MemoryCost(stream.read_named_int("Argon2-Memory"))
        argon2_passes = TimeCost(stream.read_named_int("Argon2-Passes"))
        argon2_parallelism = Parallelism(stream.read_named_int("Argon2-Parallelism"))
        argon2_salt = Salt(stream.read_named_hexbytes("Argon2-Salt"))

        return cls(
            argon2_params=argon.Argon2Params(
                type=key_derivation,
                memory_cost=argon2_memory,
                time_cost=argon2_passes,
                parallelism=argon2_parallelism,
                salt=argon2_salt,
            )
        )

    @override
    def marshal_ppk_part(self, stream: ppk.StreamWriter) -> None:
        stream.write_str(StrField(name="Key-Derivation", value=self.argon2_params.type.value))
        stream.write_int(IntField(name="Argon2-Memory", value=int(self.argon2_params.memory_cost)))
        stream.write_int(IntField(name="Argon2-Passes", value=int(self.argon2_params.time_cost)))
        stream.write_int(IntField(name="Argon2-Parallelism", value=int(self.argon2_params.parallelism)))
        stream.write_hexbytes(HexField(name="Argon2-Salt", value=bytes(self.argon2_params.salt)))

    @override
    def decrypt(self, data: EncryptedBytes, passphrase: SecretBytes | None) -> tuple[bytes, MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for decryption of {self.encryption_type}")

        return aes_decrypt(data, self.argon2_params, AES_PARAMS, passphrase)


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_AES256_CBC_Params(EncryptionParams):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME
    argon2_params: argon.Argon2Params

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @property
    @override
    def block_size(self) -> int:
        return BLOCK_SIZE

    @override
    def _encrypt(
        self, decrypted: SupportsBytes, passphrase: SecretBytes | None
    ) -> tuple[EncryptedBytes, DecryptionParams, MacKey]:
        if passphrase is None or passphrase.get_secret_value() == b"":
            raise ValueError(f"Passphrase required for encryption with {ENCRYPTION_NAME}")

        encrypted, mac_key = aes_encrypt(
            decrypted,
            self.argon2_params,
            AES_PARAMS,
            passphrase,
        )
        return (
            encrypted,
            Decryption_AES256_CBC_Params(argon2_params=self.argon2_params),
            mac_key,
        )


@dataclasses.dataclass(frozen=True, slots=True, eq=True)
class Encryption_AES256_CBC(Encryption):
    encryption_type: ClassVar[str] = ENCRYPTION_NAME

    key_derivation: ArgonID = DEFAULT_ARGON_TYPE
    argon2_memory: MemoryCost = DEFAULT_ARGON_MEMORY_COST
    argon2_passes: TimeCost = DEFAULT_ARGON_TIME_COST
    argon2_parallelism: Parallelism = DEFAULT_ARGON_PARALLELISM

    @property
    @override
    def require_passphrase(self) -> bool:
        return REQUIRE_PASSPHRASE

    @override
    def generate_params(self) -> "Encryption_AES256_CBC_Params":
        salt = gen_salt(SALT_SIZE)
        return Encryption_AES256_CBC_Params(
            argon2_params=argon.Argon2Params(
                type=self.key_derivation,
                memory_cost=self.argon2_memory,
                time_cost=self.argon2_passes,
                parallelism=self.argon2_parallelism,
                salt=salt,
            )
        )
