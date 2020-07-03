import binascii
from typing import Union

from cryptowork.algo.des import des
from cryptowork.core.settings import KEY, IV


def des_encrypt(s: str) -> bytes:
    """
    DES Encrypt
    :param s: Original String
    :return: Encrypted String, Hexadecimal
    """
    secret_key = str(KEY)
    iv = str(IV).encode()
    k = des(secret_key, iv)
    en = k.encrypt(s)
    return binascii.b2a_hex(en)


def des_descrypt(s: Union[bytes, str]) -> bytes:
    """
    DES Descrypt
    :param s: Encrypted String, Hexadecimal
    :return:  Descrypted String
    """
    secret_key = str(KEY)
    iv = str(IV).encode()
    k = des(secret_key, iv)
    de = k.decrypt(binascii.a2b_hex(s))
    return de
