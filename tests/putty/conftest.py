# import itertools
import itertools

import pytest

from ssh_key_mgr.putty.encryption.enc_aes256_cbc_argon2 import Encryption_AES256_CBC
from tests.conftest import skip_if_crypto_missing
from tests.putty.data import (
    #    ENC_AES256_CBC,
    #    KEY_NAMES,
    #    KEY_NAMES_T,
    PUTTY_AES,
    PUTTY_ARGON,
    PUTTY_ENC_NAMES,
    PUTTY_KEY_NAMES,
    #    PUTTY_ENC_NAMES,
    #    PUTTY_ENC_NAMES_T,
)

# @pytest.fixture(params=KEY_NAMES)
# def key_names(request: pytest.FixtureRequest):
#    return request.param


@pytest.fixture(params=PUTTY_ARGON.keys())
def argon_name(request: pytest.FixtureRequest):
    return request.param


@pytest.fixture(params=PUTTY_AES.keys())
def aes_name(request: pytest.FixtureRequest):
    return request.param


@pytest.fixture(params=itertools.product(PUTTY_KEY_NAMES, PUTTY_ENC_NAMES), ids=lambda x: f"{x[0]}-{x[1]}")
def key_enc_name(request: pytest.FixtureRequest) -> tuple[str, str]:
    key_name, enc_name = request.param
    if enc_name == Encryption_AES256_CBC.encryption_type.upper().replace("-", "_"):
        skip_if_crypto_missing()
    return key_name, enc_name
