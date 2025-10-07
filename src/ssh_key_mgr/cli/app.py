import pathlib

import typer

from ssh_key_mgr import openssh, putty
from ssh_key_mgr.keys import KeyPair
from ssh_key_mgr.putty import ppk
from ssh_key_mgr.secretstr import SecretBytes

app = typer.Typer()


@app.command()
def convert_key(src: pathlib.Path, dst: pathlib.Path | None = None):
    """
    Convert an SSH key from one format to another.
    """
    if dst is None:
        if src.suffix == ".ppk":
            dst = src.with_suffix(".pem")
        else:
            dst = src.with_suffix(".ppk")
    # Placeholder for actual conversion logic
    print(f"Converting key from {src} to {dst}")
    src_data = src.read_bytes()
    if openssh.can_parse_file(src_data):
        print("Source key is in OpenSSH format.")
        # Conversion logic would go here
        openssh_file = openssh.decode_file(src_data)
        match openssh_file.decryption_params:
            case openssh.DecryptionParamsAes256():
                print("Key is encrypted with AES-256.")
                passphrase = SecretBytes(typer.prompt("Enter passphrase", hide_input=True).encode())
                openssh_key = openssh_file.decrypt(passphrase)
            case openssh.DecryptionParamsNone():
                print("Key is not encrypted.")
                passphrase = None
                openssh_key = openssh_file.decrypt(passphrase)
            case _:
                print("Key has an unknown encryption method.")
                return
        keypair = KeyPair.from_openssh(openssh_key)
        putty_key = keypair.to_putty()
        if passphrase is None:
            params = putty.EncryptionParams_NONE()
        else:
            params = putty.EncryptionParams_AES256_CBC()
        putty_file = putty.PuttyFileV3.encrypt(putty_key, params, passphrase)
        putty_ppk = ppk.marshal(putty_file)
        dst.write_bytes(putty_ppk)
    elif putty.can_parse(src_data):
        print("Source key is in PuTTY format.")
        # Conversion logic would go here
    else:
        print("Unsupported key format.")


def main():
    app()
