import base58
import base64

from nacl.signing import SigningKey, VerifyKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from .javarandom import Random

class ApiContext:

    def __init__(self, seed, serverPublicKey, serverSigKey, clientPublicKey, clientPrivateKey):
        self.seed = bytes.fromhex(seed)
        self.seedHex = seed

        self.publicKey = clientPublicKey
        self.serverPubKey = serverPublicKey
        self.serverPublicKey = self.deserializePublic(serverPublicKey)
        try:
            self.serverSigKey = self.deserializePublic(serverSigKey)
        except:
            self.serverSigKey = None
        self.clientPublicKey = self.deserializePublic(clientPublicKey)
        self.clientPrivateKey = self.deserializePrivate(clientPrivateKey, None)

        self.deriveSigKeys()

    def byteArrayToLong(self, byteArray, size):
        value = 0;
        for i in range(size):
            value =  value * 256 + byteArray[i]
        return value

    def deriveSigKeys(self):
        pvk = self.clientPrivateKey.private_numbers().private_value.to_bytes(32, 'big')
        seed = self.byteArrayToLong(pvk, 6)
        rng = Random(seed)
        b = [ 0 ] * 32
        rng.nextBytes(b)
        for i in range(32):
            b[i] ^= pvk[i]
            b[i] = b[i] if b[i] >= 0 else 256 + b[i]
        s = bytes(b)
        sk = SigningKey(s)
        self.sigKeys = [ sk, sk.verify_key ]
        self.sigKey = base58.b58encode(self.sigKeys[1].encode()).decode("utf-8")

    def createEd25519Signature(self, data):
        privKey = self.sigKeys[0]
        signature = privKey.sign(data.encode('utf-8')).signature
        return base58.b58encode(signature).decode("utf-8")

    def verifyEd25519Signature(self, publicKey, signature, data):
        try:
            pubKey = VerifyKey(base58.b58decode(publicKey))
            result = pubKey.verify(data.encode('utf-8'), base58.b58decode(signature))
            return result.decode('utf-8') == data
        except:
            return False

    @staticmethod
    def generateKeys():
        curve = ec.SECP256K1()
        pk = ec.generate_private_key(curve)
        d = pk.private_numbers().private_value
        pub = pk.public_key()

        publicKey = "weave" + base58.b58encode(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)).decode()
        privateKey = base58.b58encode(d.to_bytes(32, 'big')).decode()
        return [ publicKey, privateKey ]

    def deserializePublic(self, key):
        try:
            if key.startswith("weave"):
                key = key[5:]
            curve = ec.SECP256K1()
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, base58.b58decode(key))
        except:
            try:
                return serialization.load_der_public_key(bytes.fromhex(key), default_backend())
            except:
                try:
                    return serialization.load_der_public_key(base58.b58decode(key), default_backend())
                except:
                    return serialization.load_der_public_key(base64.b64decode(key), default_backend())

    def deserializePrivate(self, key, password):
        try:
            curve = ec.SECP256K1()
            d = int(base58.b58decode(key).hex(), base=16)
            return ec.derive_private_key(d, curve)
        except:
            try:
                return serialization.load_der_private_key(bytes.fromhex(key), password, default_backend())
            except:
                return serialization.load_der_private_key(base64.b64decode(key), password, default_backend())