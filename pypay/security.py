import base64
from typing import AnyStr

from Cryptodome.Cipher import AES


__all__ = ['encrypt_string', 'decrypt_string']


def encrypt_string(encrypt_str: AnyStr, secret_key: AnyStr):
    """ AES 加密 """

    encrypt_str = encrypt_str.rjust(64)
    if isinstance(encrypt_str, str):
        encrypt_str = encrypt_str.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    cipher = AES.new(secret_key, AES.MODE_ECB)
    encrypted_str = base64.b64encode(cipher.encrypt(encrypt_str))
    return encrypted_str.decode('utf-8')


def decrypt_string(decrypt_str: AnyStr, secret_key: AnyStr):
    """ AES 解密 """

    if isinstance(decrypt_str, str):
        decrypt_str = decrypt_str.encode('utf-8')
    if isinstance(secret_key, str):
        secret_key = secret_key.encode('utf-8')
    cipher = AES.new(secret_key, AES.MODE_ECB)
    decrypted_str = cipher.decrypt(base64.b64decode(decrypt_str)).strip()
    return decrypted_str.decode('utf-8')
