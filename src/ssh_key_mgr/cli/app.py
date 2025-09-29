import enum
import pathlib
from typing import Callable

import typer

from ssh_key_mgr import openssh, putty
from ssh_key_mgr.encryption import SecretBytes
from ssh_key_mgr.file import EncryptedFile

app = typer.Typer()

formats: list[tuple[str, Callable[[bytes], bool], Callable[[bytes], EncryptedFile]]] = [
    ("OpenSSH", openssh.can_parse_file, openssh.loads),
    ("PuTTY", putty.can_parse, putty.loads),
]


def load(data: bytes):
    for fmt in formats:
        name, can_parse, loader = fmt
        if can_parse(data):
            print(f"Detected format: {name}")
            return loader(data)
    raise ValueError("Unsupported key format")


def get_passphrase(require: bool) -> SecretBytes | None:
    if require:
        return SecretBytes(typer.prompt("Enter passphrase", hide_input=True, type=str).encode())
    else:
        print("Key is not encrypted, no passphrase needed.")
        return None


class PuttyParams(enum.StrEnum):
    NONE = "none"
    AES256_CBC = "aes256-cbc"


@app.command("putty")
def _putty(src: pathlib.Path, dst: pathlib.Path | None = None, params: PuttyParams | None = None):  # pyright: ignore[reportUnusedFunction]
    src_file = load(src.read_bytes())
    passphrase = get_passphrase(src_file.require_passphrase)
    src_key = src_file.decrypt(passphrase)
    keypair = src_key.to_general_pair()
    putty_key = putty.from_general_pair(keypair)

    match params:
        case PuttyParams.NONE:
            _params = putty.Encryption_NONE()
            passphrase = None
        case PuttyParams.AES256_CBC:
            _params = putty.Encryption_AES256_CBC()
            if passphrase is None:
                passphrase = get_passphrase(True)
        case None:
            if passphrase is None:
                _params = putty.Encryption_NONE()
            else:
                _params = putty.Encryption_AES256_CBC()

    putty_file = putty.PuttyFileV3.encrypt(putty_key, _params, passphrase)

    if dst is None:
        dst = src.with_stem(src.stem + "_" + _params.encryption_type).with_suffix(".ppk")
    dst.write_bytes(putty.dumps(putty_file))


class OpenSSHParams(enum.StrEnum):
    NONE = "none"
    AES256_CTR = "aes256-ctr"


@app.command("openssh")
def _openssh(src: pathlib.Path, dst: pathlib.Path | None = None, params: OpenSSHParams | None = None):  # pyright: ignore[reportUnusedFunction]
    src_file = load(src.read_bytes())
    passphrase = get_passphrase(src_file.require_passphrase)
    src_key = src_file.decrypt(passphrase)
    keypair = src_key.to_general_pair()
    dst_key = openssh.from_general_pair(keypair)

    match params:
        case OpenSSHParams.NONE:
            _params = openssh.EncryptionNone()
            passphrase = None
        case OpenSSHParams.AES256_CTR:
            _params = openssh.EncryptionAes256()
            if passphrase is None:
                passphrase = get_passphrase(True)
        case None:
            if passphrase is None:
                _params = openssh.EncryptionNone()
            else:
                _params = openssh.EncryptionAes256()

    dst_file = openssh.EncryptedPrivateFile.encrypt(dst_key, _params, passphrase)

    if dst is None:
        dst = src.with_stem(src.stem + "_" + _params.cipher_name).with_suffix(".ppk")
    dst.write_bytes(openssh.dumps(dst_file))


def main():
    app()
