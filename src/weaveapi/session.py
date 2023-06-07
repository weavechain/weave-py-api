import base64
import time

class Session:
    def __init__(self, data, decryptedSecret):
        self.organization = data["organization"]
        self.account = data["account"]
        self.publicKey = data.get("publicKey")
        self.scopes = data["scopes"]
        self.apiKey = data["apiKey"]

        self.secret = base64.b64decode(decryptedSecret)
        self.secretExpireUTC = data["secretExpireUTC"]
        self.integrityChecks = False if data.get("integrityChecks") is None else data["integrityChecks"]
        self.nonce = 0.0
        self.tableLayoutCache = {}
        self.prevRecordsData = {}

        self.expiryCushionSec = 10

    def getNonce(self):
        self.nonce += 1
        return self.nonce

    def nearExpiry(self):
        return self.secretExpireUTC is not None and time.time() + self.expiryCushionSec > self.secretExpireUTC
