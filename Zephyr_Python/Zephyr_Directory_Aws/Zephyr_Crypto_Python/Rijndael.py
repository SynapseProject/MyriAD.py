import sys
import io
import time
import base64

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Rijndael:
    _KEYSIZE = 256
    _HASHALGO = "SHA1"
    _PWDITERATIONS = 2

    def generate_key(self, passPharseBytes: bytes, saltValueBytes: bytes):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA1(), length=Rijndael._KEYSIZE//8, salt=saltValueBytes, iterations=Rijndael._PWDITERATIONS)
        key = kdf.derive(passPharseBytes)
        return key 
    
    def Encrypt(self, plainText: str, passPhrase: str, saltValue: str, initVector: str):
        initVectorBytes = initVector.encode('ascii')
        saltValueBytes = saltValue.encode('ascii')
        passPharseBytes = passPhrase.encode('utf-8')
        plainTextBytes = plainText.encode('utf-8')

        #Encrypting using PBKDF2HMAC:
        key = Rijndael.generate_key(self, passPharseBytes=passPharseBytes, saltValueBytes=saltValueBytes)
        # Using Crypto Module
        # symmetricKey = AES.new(key, AES.MODE_CBC, initVectorBytes)
        # ciphertext = symmetricKey.encrypt(pad(plainTextBytes, AES.block_size))
        # Using Cryptography Module
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padder_data = padder.update(plainTextBytes) + padder.finalize()
        symmetricKey = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(initVectorBytes)).encryptor()
        ciphertext = symmetricKey.update(padder_data) + symmetricKey.finalize()
        return str(base64.b64encode(ciphertext).decode())
    
    def Decrypt(self, cipherText: str, passPhrase: str, saltValue: str, initVector: str):
        initVectorBytes = initVector.encode('ascii')
        saltValueBytes = saltValue.encode('ascii')
        passPharseBytes = passPhrase.encode('utf-8')
        if isinstance(cipherText, bytes) == True:
            key = Rijndael.generate_key(self, passPharseBytes=passPharseBytes, saltValueBytes=saltValueBytes)
            symmetricKey = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(initVectorBytes)).decryptor()
            ciphertext = symmetricKey.update(cipherTextBytes) + symmetricKey.finalize()

            padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            Plain_Text = padder.update(ciphertext) + padder.finalize()
            return Plain_Text.decode()
        else:
            cipherTextBytes = base64.b64decode(cipherText)

            key = Rijndael.generate_key(self, passPharseBytes=passPharseBytes, saltValueBytes=saltValueBytes)
            # Using Crypto Module
            # symmetricKey = AES.new(key, AES.MODE_CBC, initVectorBytes)
            # plainText = unpad(symmetricKey.decrypt(cipherTextBytes), AES.block_size).decode()
            # print(plainText)
            # Using Cryptography Module
            symmetricKey = Cipher(algorithm=algorithms.AES(key), mode=modes.CBC(initVectorBytes)).decryptor()
            ciphertext = symmetricKey.update(cipherTextBytes) + symmetricKey.finalize()

            padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            Plain_Text = padder.update(ciphertext) + padder.finalize()
            return Plain_Text.decode()
    
