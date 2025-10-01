import ssh_proto_types

from ssh_key_mgr.openssh import enc_aes256_ctr_bcrypt, enc_plain
from ssh_key_mgr.openssh.aes import EncryptedBytes
from ssh_key_mgr.openssh.bcrypt import Rounds, Salt
from ssh_key_mgr.secretstr import SecretBytes


def attach_padding(stream: ssh_proto_types.StreamWriter, block_size: int) -> None:
    padding = (block_size - len(stream) % block_size) % block_size  # padding
    if padding > 0:
        stream.write_raw(bytes(range(1, padding + 1)))


def verify_padding(stream: ssh_proto_types.StreamReader, block_size: int) -> None:
    padding = (block_size - stream.amount_read() % block_size) % block_size  # padding
    if padding > 0:
        pad_bytes = stream.read_raw(padding)
        if pad_bytes != bytes(range(1, padding + 1)):
            raise ValueError("Invalid padding")
    assert stream.eof()


def encrypt_plain(obj: ssh_proto_types.Packet) -> EncryptedBytes:
    stream = ssh_proto_types.StreamWriter()
    ssh_proto_types.marshal(obj, stream=stream)
    attach_padding(stream, enc_plain.BLOCK_SIZE)
    decrypted = stream.get_bytes()
    return EncryptedBytes(decrypted)


def decrypt_plain[T: ssh_proto_types.Packet](cls: type[T], encrypted: EncryptedBytes) -> T:
    decrypted = bytes(encrypted)
    stream = ssh_proto_types.StreamReader(decrypted)
    obj = ssh_proto_types.unmarshal(cls, data=stream)
    verify_padding(stream, enc_plain.BLOCK_SIZE)
    return obj


def encrypt_aes256_ctr_bcrypt(
    obj: ssh_proto_types.Packet,
    passphrase: SecretBytes,
    rounds: Rounds | None = None,
    salt: Salt | None = None,
) -> EncryptedBytes:
    # Serialize object and attach padding
    stream = ssh_proto_types.StreamWriter()
    ssh_proto_types.marshal(obj, stream=stream)
    attach_padding(stream, enc_aes256_ctr_bcrypt.BLOCK_SIZE)

    # Encrypt data
    encrypted = enc_aes256_ctr_bcrypt.encrypt(
        decrypted=stream.get_bytes(),
        passphrase=passphrase,
        rounds=rounds,
        salt=salt,
    )

    return encrypted


def decrypt_aes256_ctr_bcrypt[T: ssh_proto_types.Packet](
    cls: type[T],
    encrypted: EncryptedBytes,
    passphrase: SecretBytes,
    rounds: Rounds,
    salt: Salt,
) -> T:
    # Decrypt data
    decrypted = enc_aes256_ctr_bcrypt.decrypt(
        encrypted=encrypted,
        passphrase=passphrase,
        rounds=rounds,
        salt=salt,
    )

    # Unmarshal object and verify padding
    stream = ssh_proto_types.StreamReader(decrypted)
    obj = ssh_proto_types.unmarshal(cls, data=stream)
    verify_padding(stream, enc_aes256_ctr_bcrypt.BLOCK_SIZE)

    return obj
