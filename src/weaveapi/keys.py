import base64
import hmac
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Cipher import AES

def readKey(keyProperty, keyFileProperty):
    if keyProperty is not None:
        return keyProperty
    else:
        with open(keyFileProperty) as f:
            return f.read().replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "")

class SortedEncoder(json.JSONEncoder):
    def encode(self, obj):
        def sort_dict(item):
            if isinstance(item, dict):
                return {k: sort_dict(item[k]) for k in sorted(item.keys())}
            else:
                return item
        return super(SortedEncoder, self).encode(sort_dict(obj))

class KeyExchange:
    def __init__(self):
        self.size = AES.block_size
        self.pad_pkcs5 = lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")
        self.unpad_pkcs5 = lambda x: x[:-ord(x[-1])]

    #TODO: generateKeys

    def sharedSecret(self, privateKey, serverPublicKey):
        return privateKey.exchange(ec.ECDH(), serverPublicKey)

    def encrypt(self, secretKey, data, seed, iv):
        s = bytearray(len(iv))
        for i in range(len(iv)):
            s[i] = iv[i] ^ seed[i % len(seed)]
        aes = AES.new(secretKey, AES.MODE_CBC, s)
        return b"".join([aes.encrypt(i) for i in self.ver(secretKey, data.encode("utf-8"))])

    def decrypt(self, secretKey, data, seed, iv):
        s = bytearray(len(iv))
        for i in range(len(iv)):
            s[i] = iv[i] ^ seed[i % len(seed)]
        aes = AES.new(secretKey, AES.MODE_CBC, s)
        return self.unpad_pkcs5(aes.decrypt(data).decode("utf-8"))

    def ver(self, key, text):
        l = len(key)
        while len(text) > l:
            text_slice = text[:len(key)]
            text = text[l:]
            yield text_slice
        else:
            if len(text) == l:
                yield text
            else:
                yield self.pad_pkcs5(text, self.size)

    def signHTTP(self, secret, url, apiKey, nonce, data):
        body = str(data)
        toSign = url + "\n" + apiKey + "\n" + nonce + "\n" + ("{}" if body is None else body)
        return self.signRequest(secret, toSign)

    def signWS(self, secret, data):
        #TODO: we don't need to sign every message if we're on a secure channel
        #TODO: use pub key
        toSign = data.get("x-api-key") + \
                 "\n" + ("null" if data.get("nonce") is None else str(data.get("nonce"))) + \
                 "\n" + ("null" if data.get("signature") is None else str(data.get("signature"))) + \
                 "\n" + ("null" if data.get("organization") is None else str(data.get("organization"))) + \
                 "\n" + ("null" if data.get("account") is None else str(data.get("account"))) + \
                 "\n" + ("null" if data.get("scope") is None else str(data.get("scope"))) + \
                 "\n" + ("null" if data.get("table") is None else str(data.get("table")))
        #toSign = json.dumps(data, cls=SortedEncoder, separators=(',', ':'))
        return self.signRequest(secret, toSign)

    def signRequest(self, secret, toSign):
        sig = hmac.new(secret, msg=bytes(toSign, encoding='utf-8'), digestmod=hashlib.sha256).digest()
        return base64.b64encode(sig).decode('utf-8')
