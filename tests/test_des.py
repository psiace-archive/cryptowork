import pytest

from cryptowork.app import des_encrypt, des_descrypt

string = "Let's test cryptowork."


def test_des():
    encode = des_encrypt(string)
    decode = des_descrypt(encode).decode()
    assert decode == string
