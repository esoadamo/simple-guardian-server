from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256
from base64 import b64encode, b64decode


class AESCipher:
    block_size = 16

    def __init__(self, key):  # type: (str or bytes) -> None
        if len(key) not in [16, 24, 32]:
            key = sha256(key.encode('utf8')).hexdigest()[-32:]
        if type(key) == str:
            key = key.encode('utf8', errors='replace')
        self.key = key

    def encrypt(self, raw):
        raw = self.__pad(b64encode(raw.encode('utf8')).decode('ascii')).encode('ascii')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return 'b64;' + b64encode(iv + cipher.encrypt(raw)).decode('ascii')

    def decrypt(self, enc):
        version_legacy = not enc.startswith('b64;')
        enc = b64decode(enc[4 if not version_legacy else 0:])
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        if version_legacy:
            return self.__unpad(cipher.decrypt(enc[16:])).decode('utf8')

        return b64decode(self.__unpad(cipher.decrypt(enc[16:]))).decode('utf8')

    @staticmethod
    def __pad(s):
        return s + (AESCipher.block_size - len(s) % AESCipher.block_size) * \
               chr(AESCipher.block_size - len(s) % AESCipher.block_size)

    @staticmethod
    def __unpad(s):
        return s[:-ord(s[len(s) - 1:])]


if __name__ == '__main__':
    cypher = AESCipher("myKey")
    input_text = input('what to encrypt? ')
    enc_string = cypher.encrypt(input_text)
    decrypted_text = cypher.decrypt(enc_string)

    if decrypted_text != input_text:
        print('NOPE')
        print(input_text)
        print('================')
        print(decrypted_text)
    else:
        print('OK') 