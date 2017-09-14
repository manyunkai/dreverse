# -*-coding:utf-8 -*-
"""
Created on 2016-7-5

@author: Danny
DannyWork Project
"""

import platform

from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

py_version = platform.python_version().split('.')[0]
if py_version == '3':
    unicode = str


class DCrypto:
    def __init__(self, key, mode=AES.MODE_CFB):
        self.key = key
        self.mode = mode

    def encrypt(self, text):
        if py_version == '3' and type(text) in [str, unicode]:
            text = text.encode('utf8')

        aes = AES.new(self.key, self.mode, self.key[:16])
        cipher = aes.encrypt(text)
        return b2a_hex(cipher).decode()

    def decrypt(self, text):
        aes = AES.new(self.key, self.mode, self.key[:16])
        text = aes.decrypt(a2b_hex(text.encode()))
        return text


if __name__ == '__main__':
    t = 'HELLO PYTHON.'
    k = 'N4WrSbPgsQBwXobJSl7eytUOuydK7diu'
    print('Plain text:', t)
    print('Key:', k)

    crypto = DCrypto(k)
    e = crypto.encrypt(t)
    print(type(e))
    print('Encrypted:', e)
    print('Assert plain text equals to decrypted:', t == crypto.decrypt(e))
