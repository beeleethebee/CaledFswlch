#!/usr/bin/env python3
# coding=utf-8


from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sys


class DebateME:

    def __init__(self):
        pass

    def decrypt(self, path):
        try:
            keyFile = open("./.key", 'rb')
        except KeyError:
            print("La clé de décryptage est manquante ou inaccessible")
        key = keyFile.read()
        keyFile.close()
        f = Fernet(key)

        fileToDecrypt = open(path, 'rb')
        encryptedContent = fileToDecrypt.read()
        fileToDecrypt.close()

        decryptedContent = f.decrypt(encryptedContent)

        newFileCryptedDecrypted = open(path + '_decrypted', 'wb')
        newFileCryptedDecrypted.write(decryptedContent)
        newFileCryptedDecrypted.close()

    def encrypt(self, path):
        fileToCrypt = open(path, 'rb')
        try:
            content_fileToCrypt = fileToCrypt.read().decode("utf-8")
        except ValueError:
            print("Le fichier parait déjà assez bizarre")
            content_fileToCrypt = 0
        fileToCrypt.close()

        if content_fileToCrypt != 0:
            encrypted_content_step1 = content_fileToCrypt.encode()

            keyFile = open("./.key", 'rb')
            key = keyFile.read()
            keyFile.close()
            f = Fernet(key)

            encryptedContentFinal = f.encrypt(encrypted_content_step1)

            newFileCrypted = open(path + "_crypted", 'wb')
            newFileCrypted.write(encryptedContentFinal)
            newFileCrypted.close()

    def encode_key(self, password_provided):
        password = password_provided.encode()
        salt = b'salt_'  # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def key_int_file(self, bkey):
        file = open("./.key", 'wb')
        file.write(bkey)
        file.close()

    def get_key(self):
        file = open("./.key", 'rb')
        key = file.read()
        file.close()
        return key

    def check_passwd(self, passwd):
        provide_key = self.encode_key(passwd)
        true_key = self.get_key()
        return True if provide_key == true_key else False
