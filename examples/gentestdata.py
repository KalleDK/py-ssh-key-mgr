from ssh_key_mgr import openssh, pem
from ssh_key_mgr.openssh.bcrypt.base import Rounds, Salt
from ssh_key_mgr.secretstr import SecretBytes

PASSPHRASE = SecretBytes(b"correct horse battery staple")
ROUNDS = Rounds(16)
SALT = Salt(b"0123456789ABCDEF")
KDF_OPTS = openssh.KDFOptions(
    salt=SALT,
    rounds=ROUNDS,
)

# RSA https://datatracker.ietf.org/doc/rfc9500/
# ED25519 https://datatracker.ietf.org/doc/rfc8410/
# ED25519 https://datatracker.ietf.org/doc/rfc8032#section-5.1.5

rsa_1024_pub = openssh.OpenSSHPublicKeyRSA(
    n=124166110122983991337731418229841999167986890488136991126459644695937663637108054071234119214658061209219033982063559594860422206527401406163421984469998420544922913916890534314339062844667145883359856186081887902775389730749339136775309884506601471604371451873922100276327703518816242681897912234232574009919,
    e=65537,
)

rsa_1024_priv = openssh.OpenSSHRSAPrivateKey(
    check=openssh.OpenSSHCheck.create(123456789),
    n=rsa_1024_pub.n,
    e=rsa_1024_pub.e,
    d=50688009982610032565568554607644427510266281155982377292175432720373472282026776914137016120191064125477913776281008795045481723506326155003985409349075135333555250930208896999943793436402173025416065009528317001623325861083349036647037001868439386253544446323125514634028814260359707199682725199871422345873,
    p=12247479110638677755006895685292383938869968447801678697985070722715761107234923761151478498897073403331761752633108460282473931019601399842965881751672901,
    q=10138095276694782246202662171361003801557508450601288242196414844672242494972243383075875829566498578855752497012485563974824462328158407661799412592304819,
    iqmp=9721458286354115561136508670716762220861275896641841230665434115409468173060220159554666387496302638490101614064924388438264332619353455984953340421959387,
    comment="testRSA1024",
)

rsa_1024_plain = openssh.EncryptedPrivateFilePlain(
    public_key=rsa_1024_pub,
    encrypted_private_key=openssh.enc.encrypt_plain(rsa_1024_priv),
)

rsa_1024_enc = openssh.EncryptedPrivateFileAes256(
    public_key=rsa_1024_pub,
    kdf_opts=KDF_OPTS,
    encrypted_private_key=openssh.enc.encrypt_aes256_ctr_bcrypt(
        rsa_1024_priv,
        passphrase=PASSPHRASE,
        rounds=KDF_OPTS.rounds,
        salt=KDF_OPTS.salt,
    ),
)

ed25519_pub = openssh.OpenSSHPublicKeyEd25519(
    value=bytes.fromhex("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
)

ed25519_priv = openssh.OpenSSHEd25519PrivateKey(
    check=openssh.OpenSSHCheck.create(987654321),
    public=ed25519_pub.value,
    private=bytes.fromhex("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842") + ed25519_pub.value,
    comment="testED25519",
)

ed25519_plain = openssh.EncryptedPrivateFilePlain(
    public_key=ed25519_pub,
    encrypted_private_key=openssh.enc.encrypt_plain(ed25519_priv),
)

ed25519_enc = openssh.EncryptedPrivateFileAes256(
    public_key=ed25519_pub,
    kdf_opts=KDF_OPTS,
    encrypted_private_key=openssh.enc.encrypt_aes256_ctr_bcrypt(
        ed25519_priv,
        passphrase=PASSPHRASE,
        rounds=KDF_OPTS.rounds,
        salt=KDF_OPTS.salt,
    ),
)


def make_testdata_plain(name: str, key: openssh.EncryptedPrivateFilePlain, priv: openssh.OpenSSHPrivateKey) -> None:
    pem_file = openssh.encode_file(key)
    pem_block = pem.unmarshal(pem_file)[0]
    data_file = pem_block.data
    print()
    print(f"# region {name} - Plain")
    print()
    print(f'{name}_NONE_FILE_PEM = b"""', end="")
    print(pem_file.decode(), end="")
    print('"""')
    print()
    print(f"{name}_NONE_FILE_DATA = {data_file!r}")
    print()
    print(
        f"{name}_NONE_BLOCK = pem.PEMBlock(header='OPENSSH PRIVATE KEY', footer='OPENSSH PRIVATE KEY', data={name}_NONE_FILE_DATA)"
    )
    print()
    print(f"{name}_NONE_PRIVATE_KEY_RAW = {key.encrypted_private_key!r}")
    print()
    print(f"{name}_NONE_PUBLIC_KEY = openssh.{key.public_key!r}")
    print()
    print(f"{name}_NONE_PRIVATE_KEY = openssh.{priv!r}")
    print()
    print(f"{name}_NONE_FILE = openssh.{key!r}")
    print()
    print("# endregion")


def make_testdata_aes256(name: str, key: openssh.EncryptedPrivateFileAes256, priv: openssh.OpenSSHPrivateKey) -> None:
    pem_file = openssh.encode_file(key)
    pem_block = pem.unmarshal(pem_file)[0]
    data_file = pem_block.data
    print()
    print(f"# region {name} - AES256")
    print()
    print(f'{name}_AES256_FILE_PEM = b"""', end="")
    print(pem_file.decode(), end="")
    print('"""')
    print()
    print(f"{name}_AES256_FILE_DATA = {data_file!r}")
    print()
    print(
        f"{name}_AES256_BLOCK = pem.PEMBlock(header='OPENSSH PRIVATE KEY', footer='OPENSSH PRIVATE KEY', data={name}_AES256_FILE_DATA)"
    )
    print()
    print(f"{name}_AES256_PRIVATE_KEY_RAW = {key.encrypted_private_key!r}")
    print()
    print(f"{name}_AES256_PUBLIC_KEY = openssh.{key.public_key!r}")
    print()
    print(f"{name}_AES256_PRIVATE_KEY = openssh.{priv!r}")
    print()
    print(f"{name}_AES256_FILE = openssh.{key!r}")
    print()
    print("# endregion")


make_testdata_plain("RSA_1024", rsa_1024_plain, rsa_1024_priv)
make_testdata_aes256("RSA_1024", rsa_1024_enc, rsa_1024_priv)
make_testdata_plain("ED25519", ed25519_plain, ed25519_priv)
make_testdata_aes256("ED25519", ed25519_enc, ed25519_priv)
