from pyDes import des, CBC, PAD_PKCS5
import binascii

from cryptowork.core.settings import KEY, IV


def des_encrypt(s):
    """
    DES Encrypt
    :param s: Original String
    :return: Encrypted String, Hexadecimal
    """
    secret_key = KEY
    iv = IV.encode()
    k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    en = k.encrypt(s, padmode=PAD_PKCS5)
    return binascii.b2a_hex(en)


def des_descrypt(s):
    """
    DES Descrypt
    :param s: Encrypted String, Hexadecimal
    :return:  Descrypted String
    """
    secret_key = KEY
    iv = IV.encode()
    k = des(secret_key, CBC, iv, pad=None, padmode=PAD_PKCS5)
    de = k.decrypt(binascii.a2b_hex(s), padmode=PAD_PKCS5)
    return de
