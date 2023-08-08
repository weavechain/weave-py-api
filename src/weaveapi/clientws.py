import os
import json
import base64
import time
import traceback
import uuid
import websocket
import threading
from .futures import CompletableFuture
from .keys import KeyExchange, readKey
from .apicontext import ApiContext
from .session import Session
from .utils import *

MAX_TRIES = 100

class ClientWs:

    def __init__(self, config):
        self.config = config
        self.websocket = None
        self.encryption = self.config.get("encryption") is not None and self.config["encryption"]

        self.keyExchange = KeyExchange()

    def init(self):
        cfg = self.config["websocket"]

        self.pendingRequests = {}

        self.apiUrl = ("wss" if cfg["useWss"] else "ws") + "://" + parse_host(cfg["host"]) + ":" + str(cfg["port"])
        #print(self.apiUrl)

        self.thread = threading.Thread(target=self.wsloop, daemon=True)
        self.thread.start()

        nTry = 0
        while self.websocket is None and nTry < MAX_TRIES:
            print("Waiting connection...")
            nTry += 1
            time.sleep(1)
        print("Connected")

        if not self.websocket is None:
            serverPublicKey = self.publicKey().get()["data"]
            self.serverSigKey = self.sigKey().get()["data"]
            clientPublicKey = readKey(self.config.get("publicKey"), self.config.get("publicKeyFile"))
            clientPrivateKey = readKey(self.config.get("privateKey"), self.config.get("privateKeyFile"))
            self.clientPublicKey = clientPublicKey
            self.clientPrivateKey = clientPrivateKey

            self.apiContext = ApiContext(
                self.config["seed"],
                serverPublicKey,
                self.serverSigKey,
                clientPublicKey,
                clientPrivateKey
            )
            self.secretKey = self.keyExchange.sharedSecret(self.apiContext.clientPrivateKey, self.apiContext.serverPublicKey)
            #print([b if b < 128 else b - 256 for b in bytes.fromhex(serverPublicKey)])

    def close(self):
        if self.ws is not None:
            self.ws.close()

    def on_message(self, ws, message):
        try:
            #print("Received: " + message)

            data = json.loads(message)
            id = data.get("id")
            req = None if id is None else self.pendingRequests.get(id)
            if req is not None:
                reply = data.get("reply")

                if  reply["res"] == "fwd":
                    r = json.loads(reply["data"])
                    data = base64.b64decode(r["msg"])
                    decrypted = self.keyExchange.decrypt(self.secretKey, data, self.apiContext.seed, bytes.fromhex(r["x-iv"]))
                    reply = json.loads(decrypted)

                if reply is not None and reply.get("target") is not None \
                        and reply["target"].get("operationType") is not None \
                        and reply.get("data") is not None \
                        and reply["target"].get("operationType").lower() == "login":
                    sdata = json.loads(reply["data"])
                    secret = bytes.fromhex(sdata["secret"])
                    iv = bytes.fromhex(sdata["x-iv"])
                    decryptedSecret = self.keyExchange.decrypt(self.secretKey, secret, self.apiContext.seed, iv)
                    del sdata["secret"]
                    req.done(Session(sdata, decryptedSecret))
                else:
                    try:
                        output = json.loads(reply) if isinstance(reply, str) else reply
                    except:
                        output = reply
                    req.done(output)
        except Exception as e:
            print("ERROR: Failed parsing message")
            print(traceback.format_exc())

    def on_error(self, ws, error):
        print(error)

    def on_close(self, ws, close_status_code, close_msg):
        print("websocket closed")

    def on_open(self, ws):
        self.websocket = ws
        #ws.keep_running = False

    def wsloop(self):
        print("Listening for events...")
        #websocket.enableTrace(True)
        self.ws = websocket.WebSocketApp(
            self.apiUrl,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        self.ws.run_forever()

    def request(self, data, isAuth = True):
        id = str(uuid.uuid4()).replace("-", "")
        data["id"] = id

        future = CompletableFuture(None)
        self.pendingRequests[id] = future

        msg = json.dumps(data)
        if isAuth and self.encryption:
            iv = os.urandom(16)
            encrypted = self.keyExchange.encrypt(self.secretKey, msg, self.apiContext.seed, iv)

            request = {
                "id": id,
                "type": "enc",
                "x-enc": base64.b64encode(encrypted).decode('ascii'),
                "x-iv": iv.hex(),
                "x-key": self.apiContext.publicKey
            }

            self.websocket.send(json.dumps(request))
        else:
            #print("Sending: " + msg)
            self.websocket.send(msg)
        return future

    def version(self):
        return self.request({ "type": "version" }, False)

    def ping(self):
        return self.request({ "type": "ping" }, False)

    def publicKey(self):
        return self.request({ "type": "public_key" }, False)

    def sigKey(self):
        return self.request({ "type": "sig_key" }, False)

    def signString(self, toSign, iv):
        signed = self.keyExchange.encrypt(self.secretKey, toSign, self.apiContext.seed, iv)
        return signed.hex()

    def login(self, organization, account, scopes, credentials = None):
        toSign = organization + "\n" + self.clientPublicKey + "\n" + scopes
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        return self.request({
            "type": "login",
            "organization": organization,
            "account": account if account is not None and len(account) > 0 else self.clientPublicKey,
            "scopes": scopes,
            "credentials": credentials,
            "signature": signature,
            "x-iv": iv.hex(),
            "x-key": self.apiContext.publicKey,
            "x-sig-key": self.apiContext.sigKey,
            "x-dlg-sig": self.apiContext.createEd25519Signature(self.apiContext.serverPubKey),
            "x-own-sig": self.apiContext.createEd25519Signature(self.apiContext.publicKey)
        })

    def authPost(self, session, data):
        data["x-api-key"] = session.apiKey
        data["x-nonce"] = session.getNonce()

        signature = self.keyExchange.signWS(session.secret, data)
        data["x-sig"] = signature

        return self.request(data)

    def logout(self, session):
        return self.authPost(session, {
            "type": "logout",
            "organization": session.organization,
            "account": session.account
        })

    def status(self, session):
        return self.authPost(session, {
            "type": "status",
            "organization": session.organization,
            "account": session.account
        })

    def terms(self, session, options):
        return self.authPost(session, {
            "type": "terms",
            "organization": session.organization,
            "account": session.account,
            "options": options.toJson()
        })

    def createTable(self, session, scope, table, createOptions):
        return self.authPost(session, {
            "type": "create",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": createOptions.toJson()
        })

    def dropTable(self, session, scope, table):
        return self.authPost(session, {
            "type": "drop",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        })

    def updateLayout(self, session, scope, table, layout):
        return self.authPost(session, {
            "type": "update_layout",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "layout": layout if isinstance(layout, str) else json.dumps(layout)
        })

    def updateConfig(self, session, path, values):
        return self.authPost(session, {
            "type": "update_config",
            "organization": session.organization,
            "account": session.account,
            "path": path,
            "values": values if isinstance(values, str) else json.dumps(values)
        })

    def grantRole(self, session, account, roles):
        return self.authPost(session, {
            "type": "grant_role",
            "organization": session.organization,
            "account": session.account,
            "targetAccount": account,
            "roles": roles if isinstance(roles, str) else json.dumps(roles)
        })

    def write(self, session, scope, records, writeOptions):
        if session.integrityChecks:
            layout = self.getLayout(session, scope, records.table)
            records.integrity = integritySignature(self.clientPublicKey, session, scope, records, layout, self.keyExchange.signRequest, self.apiContext.seedHex, self.apiContext.createEd25519Signature)

        message = {
            "type": "write",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": records.table,
            "enc": "json",
            "records": records.toJson(),
            "options": writeOptions.toJson()
        }
        return self.authPost(session, message)

    def getLayout(self, session, scope, table):
        key = scope + ":" + table
        layout = session.tableLayoutCache.get(key)
        if layout is None:
            res = self.getTableDefinition(session, scope, table).get()
            if res.get("data") is not None:
                layout = (json.loads(res["data"]) if isinstance(res["data"], str) else res["data"]).get("layout")
                session.tableLayoutCache[key] = layout
        return layout

    def read(self, session, scope, table, filter, readOptions):
        data = {
            "type": "read",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def count(self, session, scope, table, filter, readOptions):
        data = {
            "type": "count",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def delete(self, session, scope, table, filter, deleteOptions):
        data = {
            "type": "delete",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": deleteOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)


    def subscribe(self, session, scope, table, filter, subscribeOptions, updateHandler):
        data = {
            "type": "subscribe",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": subscribeOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def unsubscribe(self, session, subscriptionId):
        data = {
            "type": "unsubscribe",
            "organization": session.organization,
            "account": session.account,
            "subscriptionId": subscriptionId
        }

        return self.authPost(session, data)

    def downloadTable(self, session, scope, table, filter, format, readOptions):
        data = {
            "type": "download_table",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "format": format,
            "options": readOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def downloadDataset(self, session, did, readOptions):
        data = {
            "type": "download_dataset",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "options": readOptions.toJson()
        }

        return self.authPost(session, data)

    def publishDataset(self, session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions):
        data = {
            "type": "publish_dataset",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "name": name,
            "description": description,
            "license": license,
            "metadata": metadata,
            "weave": weave,
            "full_description": fullDescription,
            "logo": logo,
            "category": category,
            "scope": scope,
            "table": table,
            "format": format,
            "price": price,
            "token": token,
            "pageorder": pageorder,
            "options": publishOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def enableProduct(self, session, did, productType, active):
        data = {
            "type": "enable_product",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "productType": productType,
            "active": active
        }

        return self.authPost(session, data)

    def runTask(self, session, did, computeOptions):
        data = {
            "type": "run_task",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "options": computeOptions.toJson()
        }

        return self.authPost(session, data)

    def publishTask(self, session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions):
        data = {
            "type": "publish_task",
            "organization": session.organization,
            "account": session.account,
            "did": did,
            "name": name,
            "description": description,
            "license": license,
            "metadata": metadata,
            "weave": weave,
            "full_description": fullDescription,
            "logo": logo,
            "category": category,
            "task": task,
            "price": price,
            "token": token,
            "pageorder": pageorder,
            "options": publishOptions.toJson()
        }

        return self.authPost(session, data)

    def hashes(self, session, scope, table, filter, readOptions):
        data = {
            "type": "hashes",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": readOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def hashCheckpoint(self, session, enable):
        data = {
            "type": "hash_checkpoint",
            "organization": session.organization,
            "account": session.account,
            "options": enable
        }
        return self.authPost(session, data)

    def zkProof(self, session, scope, table, gadget, params, fields, filter, zkOptions):
        data = {
            "type": "zk_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "gadget": gadget,
            "params": params,
            "fields": fields if isinstance(fields, str) else json.dumps(fields),
            "options": zkOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def zkDataProof(self, session, gadget, params, values, zkOptions):
        data = {
            "type": "zk_data_proof",
            "organization": session.organization,
            "account": session.account,
            "gadget": gadget,
            "params": params,
            "values": values if isinstance(values, str) else json.dumps(values),
            "options": zkOptions.toJson()
        }

        return self.authPost(session, data)

    def verifyZkProof(self, session, proof, gadget, params, commitment, nGenerators):
        data = {
            "type": "zk_proof",
            "organization": session.organization,
            "account": session.account,
            "proof": proof,
            "gadget": gadget,
            "params": params,
            "commitment": commitment,
            "nGenerators": nGenerators
        }

        return self.authPost(session, data)


    def taskLineage(self, session, taskId):
        data = {
            "type": "task_lineage",
            "organization": session.organization,
            "account": session.account,
            "taskId": taskId
        }

        return self.authPost(session, data)

    def verifyTaskLineage(self, session, lineageData):
        data = {
            "type": "verify_task_lineage",
            "organization": session.organization,
            "account": session.account,
            "lineageData": lineageData
        }

        return self.authPost(session, data)

    def taskOutputData(self, session, taskId, options):
        data = {
            "type": "task_output_data",
            "organization": session.organization,
            "account": session.account,
            "taskId": taskId,
            "options": options.toJson()
        }

        return self.authPost(session, data)

    def mpc(self, session, scope, table, algo, fields, filter, mpcOptions):
        data = {
            "type": "mpc",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "algo": algo,
            "fields": fields if isinstance(fields, str) else json.dumps(fields),
            "options": mpcOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def storageProof(self, session, scope, table, filter, challenge, options):
        data = {
            "type": "storage_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def zkStorageProof(self, session, scope, table, filter, challenge, options):
        data = {
            "type": "zk_storage_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def merkleTree(self, session, scope, table, filter, salt, digest, options):
        data = {
            "type": "merkle_tree",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "options": options.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def merkleProof(self, session, scope, table, hash, digest = None):
        data = {
            "type": "merkle_proof",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "digest": digest,
            "hash": hash
        }

        return self.authPost(session, data)

    def zkMerkleTree(self, session, scope, table, filter, salt, digest, rounds, seed, options):
        data = {
            "type": "zk_merkle_tree",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "rounds": rounds,
            "seed": seed,
            "options": options.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def rootHash(self, session, scope, table):
        data = {
            "type": "root_hash",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }

        return self.authPost(session, data)

    def mimcHash(self, session, data, rounds, seed):
        pdata = {
            "type": "mimc_hash",
            "organization": session.organization,
            "account": session.account,
            "data": data,
            "rounds": rounds,
            "seed": seed
        }

        return self.authPost(session, pdata)

    def proofsLastHash(self, session, scope, table):
        pdata = {
            "type": "proofs_last_hash",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }

        return self.authPost(session, pdata)

    def updateProofs(self, session, scope, table):
        pdata = {
            "type": "update_proofs",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }

        return self.authPost(session, pdata)

    def verifyMerkleHash(self, session, tree, hash, digest):
        data = {
            "type": "verify_merkle_hash",
            "tree": tree,
            "hash": hash,
            "digest": digest
        }

        return self.authPost(session, data)

    def compute(self, session, image, computeOptions):
        data = {
            "type": "compute",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": None if computeOptions is None else computeOptions.toJson()
        }

        return self.authPost(session, data)

    def getImage(self, session, image, localOutputFolder, computeOptions):
        return "Not implemented"

    def flearn(self, session, image, flOptions):
        data = {
            "type": "f_learn",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": None if flOptions is None else flOptions.toJson()
        }

        return self.authPost(session, data)
    
    def splitLearn(self, session, serverImage, clientImage, slOptions):
        data = {
            "type": "split_learn",
            "organization": session.organization,
            "account": session.account,
            "serverImage": serverImage,
            "clientImage": clientImage,
            "options": None if slOptions is None else slOptions.toJson()
        }

        return self.authPost(session, data)


    def balance(self, session, accountAddress, scope, token):
        toSign = session.organization + "\n" + self.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "type": "balance",
            "organization": session.organization,
            "account": session.account,
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "signature": signature,
            "x-iv": iv.hex()
        }

        return self.authPost(session, data)

    def transfer(self, session, accountAddress, scope, token, amount):
        toSign = session.organization + "\n" + self.clientPublicKey + "\n" + accountAddress + "\n" + scope + "\n" + token + "\n" + str(amount)
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "type": "transfer",
            "organization": session.organization,
            "account": session.account,
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "amount": amount,
            "signature": signature,
            "x-iv": iv.hex()
        }

        return self.authPost(session, data)

    def call(self, session, contractAddress, scope, fn, data):
        serialized = base64.b64encode(data).decode('ascii')
        toSign = session.organization + "\n" + self.clientPublicKey + "\n" + contractAddress + "\n" + scope + "\n" + fn + "\n" + serialized
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "type": "call",
            "organization": session.organization,
            "account": session.account,
            "accountAddress": contractAddress,
            "scope": scope,
            "function": fn,
            "data": serialized,
            "signature": signature,
            "x-iv": iv.hex()
        }

        return self.authPost(session, data)

    def updateFees(self, session, scope, fees):
        toSign = session.organization + "\n" + self.clientPublicKey + "\n" + scope + "\n" + fees
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "type": "update_fees",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "fees": fees,
            "signature": signature,
            "x-iv": iv.hex()
        }

        return self.authPost(session, data)

    def contractState(self, session, contractAddress, scope):
        toSign = session.organization + "\n" + self.clientPublicKey + "\n" + contractAddress + "\n" + scope
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "type": "contract_state",
            "organization": session.organization,
            "account": session.account,
            "contractAddress": contractAddress,
            "scope": scope,
            "signature": signature,
            "x-iv": iv.hex()
        }

        return self.authPost(session, data)

    def subscribe(self, session, scope, table, filter, subscribeOptions):
        data = {
            "type": "read",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": subscribeOptions.toJson()
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def getSidechainDetails(self, session):
        data = {
            "type": "get_sidechain_details",
        }
        return self.authPost(session, data)

    def getUserDetails(self, session, publicKey):
        data = {
            "type": "get_user_details",
            "publicKey": publicKey
        }
        return self.authPost(session, data)

    def getNodes(self, session):
        data = {
            "type": "get_nodes",
        }
        return self.authPost(session, data)

    def getScopes(self, session):
        data = {
            "type": "get_scopes",
        }
        return self.authPost(session, data)

    def getTables(self, session, scope):
        data = {
            "type": "get_tables",
            "scope": scope
        }
        return self.authPost(session, data)

    def getNodeConfig(self, session, nodePublicKey):
        data = {
            "type": "get_node_config",
            "nodePublicKey": nodePublicKey
        }
        return self.authPost(session, data)

    def getAccountNotifications(self, session):
        data = {
            "type": "get_account_notifications",
        }
        return self.authPost(session, data)

    def getTableDefinition(self, session, scope, table):
        data = {
            "type": "get_table_definition",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }

        return self.authPost(session, data)

    def history(self, session, scope, table, filter, historyOptions):
        data = {
            "type": "history",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table,
            "options": historyOptions.toJson()
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def writers(self, session, scope, table, filter):
        data = {
            "type": "writers",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def tasks(self, session, scope, table, filter):
        data = {
            "type": "tasks",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def lineage(self, session, scope, table, filter):
        data = {
            "type": "lineage",
            "organization": session.organization,
            "account": session.account,
            "scope": scope,
            "table": table
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, data)

    def deployOracle(self, session, oracleType, targetBlockchain, source, deployOptions):
        data = {
            "type": "deploy_oracle",
            "organization": session.organization,
            "account": session.account,
            "oracleType": oracleType,
            "targetBlockchain": targetBlockchain,
            "source": source,
            "options": None if deployOptions is None else json.dumps(deployOptions)
        }

        return self.authPost(session, data)

    def deployFeed(self, session, image, options):
        data = {
            "type": "deploy_feed",
            "organization": session.organization,
            "account": session.account,
            "image": image,
            "options": None if options is None else json.dumps(options)
        }

        return self.authPost(session, data)

    def removeFeed(self, session, feedId):
        data = {
            "type": "remove_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId
        }

        return self.authPost(session, data)

    def startFeed(self, session, feedId, options):
        data = {
            "type": "start_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId,
            "options": None if options is None else options.toJson(),
        }

        return self.authPost(session, data)

    def stopFeed(self, session, feedId):
        data = {
            "type": "stop_feed",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId
        }

        return self.authPost(session, data)

    def forwardApi(self, session, feedId, params):
        data = {
            "type": "forward_api",
            "organization": session.organization,
            "account": session.account,
            "feedId": feedId,
            "params": None if params is None else params if isinstance(params, str) else json.dumps(params)
        }

        return self.authPost(session, data)

    def uploadApi(self, session, params):
        data = {
            "type": "upload_api",
            "organization": session.organization,
            "account": session.account,
            "params": None if params is None else params if isinstance(params, str) else json.dumps(params)
        }

        return self.authPost(session, data)

    def heGetInputs(self, session, datasources, args):
        data = {
            "type": "he_get_inputs",
            "organization": session.organization,
            "account": session.account,
            "datasources": None if datasources is None else json.dumps(datasources),
            "args": None if args is None else args if isinstance(args, str) else json.dumps(args)
        }

        return self.authPost(session, data)

    def heGetOutputs(self, session, encoded, args):
        data = {
            "type": "he_get_outputs",
            "organization": session.organization,
            "account": session.account,
            "encoded": encoded,
            "args": None if args is None else args if isinstance(args, str) else json.dumps(args)
        }

        return self.authPost(session, data)

    def heEncode(self, session, items):
        data = {
            "type": "he_encode",
            "organization": session.organization,
            "account": session.account,
            "args": items if isinstance(items, str) else json.dumps(items)
        }

        return self.authPost(session, data)

    def postMessage(self, session, targetInboxKey, message, options):
        data = {
            "type": "post_message",
            "organization": session.organization,
            "account": session.account,
            "targetInboxKey": targetInboxKey,
            "message": message if isinstance(message, str) else json.dumps(message),
            "options": options if isinstance(options, str) else json.dumps(options)
        }

        return self.authPost(session, data)

    def pollMessages(self, session, inboxKey, options):
        data = {
            "type": "poll_messages",
            "organization": session.organization,
            "account": session.account,
            "inboxKey": inboxKey,
            "options": options if isinstance(options, str) else json.dumps(options)
        }

        return self.authPost(session, data)

    def issueCredentials(self, session, issuer, holder, credentials, options):
        data = {
            "type": "issue_credentials",
            "organization": session.organization,
            "account": session.account,
            "issuer": issuer,
            "holder": holder,
            "credentials": credentials if isinstance(credentials, str) else json.dumps(credentials),
            "options": None if options is None else options.toJson()
        }

        return self.authPost(session, data)

    def verifyCredentials(self, session, credentials, options):
        data = {
            "type": "verify_credentials",
            "organization": session.organization,
            "account": session.account,
            "credentials": credentials if isinstance(credentials, str) else json.dumps(credentials),
            "options": None if options is None else options.toJson()
        }

        return self.authPost(session, data)

    def createPresentation(self, session, credentials, subject, options):
        data = {
            "type": "create_presentation",
            "organization": session.organization,
            "account": session.account,
            "credentials": credentials if isinstance(credentials, str) else json.dumps(credentials),
            "subject": subject,
            "options": None if options is None else options.toJson()
        }

        return self.authPost(session, data)

    def signPresentation(self, session, presentation, domain, challenge, options):
        data = {
            "type": "sign_presentation",
            "organization": session.organization,
            "account": session.account,
            "presentation": presentation if isinstance(presentation, str) else json.dumps(presentation),
            "domain": domain,
            "challenge": challenge,
            "options": None if options is None else options.toJson()
        }

        return self.authPost(session, data)

    def verifyPresentation(self, session, presentation, domain, challenge, options):
        data = {
            "type": "verify_presentation",
            "organization": session.organization,
            "account": session.account,
            "presentation": presentation if isinstance(presentation, str) else json.dumps(presentation),
            "domain": domain,
            "challenge": challenge,
            "options": None if options is None else options.toJson()
        }

        return self.authPost(session, data)

    def verifyDataSignature(self, session, signer, signature, toSign):
        data = {
            "type": "verify_data_signature",
            "organization": session.organization,
            "account": session.account,
            "signer": signer,
            "signature": signature,
            "data": toSign if isinstance(toSign, str) else json.dumps(toSign)
        }

        return self.authPost(session, data)

    def createUserAccount(self, session, organization, account, publicKey, roles):
        data = {
            "type": "create_user_account",
            "organization": session.organization,
            "account": session.account,
            "targetOrganization": organization,
            "targetAccount": account,
            "publicKey": publicKey,
            "roles": roles
        }

        return self.authPost(session, data)

    def resetConfig(self, session):
        data = {
            "type": "reset_config",
        }
        return self.authPost(session, data)

    def withdraw(self, session, token, amount):
        data = {
            "type": "withdraw",
            "organization": session.organization,
            "account": session.account,
            "token": token,
            "amount": amount
        }

        return self.authPost(session, data)

    def withdrawAuthorize(self, session, token, address):
        toSign = token + "\n" + address
        data = {
            "type": "withdraw",
            "organization": session.organization,
            "account": session.account,
            "token": token,
            "address": address,
            "signature": self.apiContext.createEd25519Signature(toSign)
        }

        return self.authPost(session, data)

    def emailAuth(self, org, clientPubKey, targetWebUrl, email):
        toSign = clientPubKey + "\n" + email
        signature = self.apiContext.createEd25519Signature(toSign)

        data = {
            "organization": org,
            "clientPubKey": clientPubKey,
            "targetEmail": email,
            "targetWebUrl": targetWebUrl,
            "signature": signature,
            "x-sig-key": self.apiContext.sigKey
        }

        encodedData = base64.b64encode(json.dumps(data)).decode("ascii")
        return self.request(encodedData, False)