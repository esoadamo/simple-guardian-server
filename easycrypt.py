import base64
# noinspection PyPackageRequirements
from Crypto.Cipher import AES
# noinspection PyPackageRequirements
from Crypto import Random
from hashlib import sha256


class AESCipher:
    block_size = 16

    def __init__(self, key):
        if len(key) not in [16, 24, 32]:
            key = sha256(key.encode('utf8')).hexdigest()[-32:]
        self.key = key

    def encrypt(self, raw):
        raw = self.__pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('ascii')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.__unpad(cipher.decrypt(enc[16:])).decode('utf8')

    @staticmethod
    def __pad(s):
        return s + (AESCipher.block_size - len(s) % AESCipher.block_size) * \
               chr(AESCipher.block_size - len(s) % AESCipher.block_size)

    @staticmethod
    def __unpad(s):
        return s[:-ord(s[len(s) - 1:])]


if __name__ == '__main__':
    cypher = AESCipher("myKey")
    enc_string = cypher.encrypt("hello world")
    print(enc_string)
    cypher2 = AESCipher("yourKey")
    print(cypher2.decrypt(enc_string))
