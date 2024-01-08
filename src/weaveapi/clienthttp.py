import json
import os
import base64
import base58
import requests
import tempfile
from .futures import CompletableFuture
from .apicontext import ApiContext
from .keys import KeyExchange, readKey
from .session import Session
from .utils import *


class ClientHttp:
    def __init__(self, config):
        self.config = config
        self.version = "v1"
        self.encryption = (
            self.config.get("encryption") is not None and self.config["encryption"]
        )

        self.keyExchange = KeyExchange()

    def init(self):
        cfg = self.config["http"]

        # TODO: async calls
        self.apiUrl = (
            ("https" if cfg["useHttps"] else "http")
            + "://"
            + parse_host(cfg["host"])
            + ":"
            + str(cfg["port"])
        )
        # print(self.apiUrl)

        serverPublicKey = self.publicKey().get()["data"]
        self.serverSigKey = self.sigKey().get()["data"]
        clientPublicKey = readKey(
            self.config.get("publicKey"), self.config.get("publicKeyFile")
        )
        clientPrivateKey = readKey(
            self.config.get("privateKey"), self.config.get("privateKeyFile")
        )
        self.clientPublicKey = clientPublicKey
        self.clientPrivateKey = clientPrivateKey

        self.apiContext = ApiContext(
            self.config["seed"],
            serverPublicKey,
            self.serverSigKey,
            clientPublicKey,
            clientPrivateKey,
        )
        self.secretKey = self.keyExchange.sharedSecret(
            self.apiContext.clientPrivateKey, self.apiContext.serverPublicKey
        )

    def close(self):
        pass

    def version(self):
        reply = requests.get(self.apiUrl + "/version")
        return reply.content.decode("utf-8")

    def get(self, call):
        url = self.apiUrl + "/" + self.version + "/" + call
        # print(url)
        reply = requests.get(url)
        return reply.content.decode("utf-8")

    def post(self, call, data, headers):
        if self.encryption:
            url = self.apiUrl + "/" + self.version + "/enc"

            request = self.encrypt(call, data, headers)

            reply = requests.post(url, json=request, headers=headers)
            content = reply.content.decode("utf-8")
            try:
                output = (
                    json.loads(content) if isinstance(content, str) else content
                )  # TODO: consistent handling
            except:
                output = content

            output = self.decrypt(output)

            return output
        else:
            url = self.apiUrl + "/" + self.version + "/" + call
            reply = requests.post(url, json=data, headers=headers)
            content = reply.content.decode("utf-8")
            try:
                output = (
                    json.loads(content) if isinstance(content, str) else content
                )  # TODO: consistent handling
            except:
                output = content
            return output

    def download(self, call, data, headers):
        fileName = data["localOutputFolder"].rstrip('/') + "/" + data["imageName"]
        if self.encryption:
            url = self.apiUrl + "/" + self.version + "/enc"

            request = self.encrypt(call, data, headers)
            
            with requests.post(url, json=request, headers=headers, stream=True) as r:
                r.raise_for_status()
                output = self.decrypt(r.content.decode("utf-8"))
                with open(fileName, "wb") as f:
                    for chunk in output.iter_content(chunk_size=2048):
                        f.write(chunk)

            return fileName
        else:
            url = self.apiUrl + "/" + self.version + "/" + call

            with requests.post(url, json=data, headers=headers, stream=True) as r:
                r.raise_for_status()
                with open(fileName, "wb") as f:
                    for chunk in r.iter_content(chunk_size=2048):
                        f.write(chunk)
                        
            return fileName

    def ping(self):
        return CompletableFuture(self.get("ping"))

    def publicKey(self):
        return CompletableFuture(json.loads(self.get("public_key")))

    def sigKey(self):
        return CompletableFuture(json.loads(self.get("sig_key")))

    def signString(self, toSign, iv):
        signed = self.keyExchange.encrypt(
            self.secretKey, toSign, self.apiContext.seed, iv
        )
        return signed.hex()

    def login(self, organization, account, scopes, credentials=None):
        toSign = organization + "\n" + self.clientPublicKey + "\n" + scopes
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        reply = self.post(
            "login",
            {
                "organization": organization,
                "account": account
                if account is not None and len(account) > 0
                else self.clientPublicKey,
                "scopes": scopes,
                "signature": signature,
                "credentials": credentials,
                "x-iv": iv.hex(),
                "x-key": self.apiContext.publicKey,
                "x-sig-key": self.apiContext.sigKey,
                "x-dlg-sig": self.apiContext.createEd25519Signature(
                    self.apiContext.serverPubKey
                ),
                "x-own-sig": self.apiContext.createEd25519Signature(
                    self.apiContext.publicKey
                ),
            },
            None,
        )

        if reply.get("data") is None:
            print(reply)
        data = json.loads(reply["data"])
        secret = bytes.fromhex(data["secret"])
        iv2 = bytes.fromhex(data["x-iv"])
        decryptedSecret = self.keyExchange.decrypt(
            self.secretKey, secret, self.apiContext.seed, iv2
        )

        del data["secret"]
        return CompletableFuture(Session(data, decryptedSecret))

    def authPost(self, session, call, data):
        headers = self.buildHeaders(session, call, data)

        return CompletableFuture(self.post(call, data, headers))

    def authDownload(self, session, call, data):
        headers = self.buildHeaders(session, call, data)
        headers["Accept-Encoding"] = "gzip;q=0,deflate;q=0";

        return self.download(call, data, headers)

    def logout(self, session):
        return self.authPost(session, "logout", {})

    def status(self, session):
        return self.authPost(session, "status", {})

    def terms(self, session, scope, table, options):
        return self.authPost(
            session,
            "terms",
            {"scope": scope, "table": table, "options": options.toJson()},
        )

    def createTable(self, session, scope, table, createOptions):
        return self.authPost(
            session,
            "create",
            {"scope": scope, "table": table, "options": createOptions.toJson()},
        )

    def dropTable(self, session, scope, table):
        return self.authPost(session, "drop", {"scope": scope, "table": table})

    def updateLayout(self, session, scope, table, layout):
        return self.authPost(
            session,
            "update_layout",
            {
                "scope": scope,
                "table": table,
                "layout": layout if isinstance(layout, str) else json.dumps(layout),
            },
        )

    def updateConfig(self, session, path, values):
        return self.authPost(
            session,
            "update_config",
            {
                "path": path,
                "values": values if isinstance(values, str) else json.dumps(values),
            },
        )

    def grantRole(self, session, account, roles):
        return self.authPost(
            session,
            "grant_role",
            {
                "targetAccount": account,
                "roles": roles if isinstance(roles, str) else json.dumps(roles)
            }
        )

    def write(self, session, scope, records, writeOptions):
        if session.integrityChecks:
            layout = self.getLayout(session, scope, records.table)
            records.integrity = integritySignature(
                self.clientPublicKey,
                session,
                scope,
                records,
                layout,
                self.keyExchange.signRequest,
                self.apiContext.seedHex,
                self.apiContext.createEd25519Signature,
            )

        message = {
            "scope": scope,
            "table": records.table,
            "enc": "json",
            "records": records.toJson(),
            "options": writeOptions.toJson(),
        }
        return self.authPost(session, "write", message)

    def getLayout(self, session, scope, table):
        key = scope + ":" + table
        layout = session.tableLayoutCache.get(key)
        if layout is None:
            res = self.getTableDefinition(session, scope, table).get()
            if res.get("data") is not None:
                layout = (
                    json.loads(res["data"])
                    if isinstance(res["data"], str)
                    else res["data"]
                ).get("layout")
                session.tableLayoutCache[key] = layout
        return layout

    def read(self, session, scope, table, filter, readOptions):
        data = {"scope": scope, "table": table, "options": readOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "read", data)

    def readStream(self, session, scope, table, filter, readOptions, localOutputFolder, fileName):
        data = {"scope": scope, "table": table, "options": readOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        if readOptions.stream is not None and readOptions.stream:
            data["localOutputFolder"] = localOutputFolder
            data["imageName"] = fileName
            return self.authDownload(session, "read", data)
        else:
            return self.authPost(session, "read", data)

    def readReceipts(self, session):
        data = {}
        return self.authPost(session, "read_receipts", data)

    def count(self, session, scope, table, filter, readOptions):
        data = {"scope": scope, "table": table, "options": readOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "count", data)

    def delete(self, session, scope, table, filter, deleteOptions):
        data = {"scope": scope, "table": table, "options": deleteOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "delete", data)

    def subscribe(self, session, scope, table, filter, subscribeOptions, updateHandler):
        data = {"scope": scope, "table": table, "options": subscribeOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "subscribe", data)

    def unsubscribe(self, session, subscriptionId):
        data = {"subscriptionId": subscriptionId}

        return self.authPost(session, "unsubscribe", data)

    def downloadTable(self, session, scope, table, filter, format, readOptions):
        data = {
            "scope": scope,
            "table": table,
            "format": format,
            "options": readOptions.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "download_table", data)

    def downloadDataset(self, session, did, readOptions):
        data = {"did": did, "options": readOptions.toJson()}

        return self.authPost(session, "download_dataset", data)

    def publishDataset(
        self,
        session,
        did,
        name,
        description,
        license,
        metadata,
        weave,
        fullDescription,
        logo,
        category,
        scope,
        table,
        filter,
        format,
        price,
        token,
        pageorder,
        publishOptions,
    ):
        data = {
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
            "options": publishOptions.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "publish_dataset", data)

    def enableProduct(self, session, did, productType, active):
        data = {"did": did, "productType": productType, "active": active}

        return self.authPost(session, "enable_product", data)

    def runTask(self, session, did, computeOptions):
        data = {"did": did, "options": computeOptions.toJson()}

        return self.authPost(session, "run_task", data)

    def publishTask(
        self,
        session,
        did,
        name,
        description,
        license,
        metadata,
        weave,
        fullDescription,
        logo,
        category,
        task,
        price,
        token,
        pageorder,
        publishOptions,
    ):
        data = {
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
            "options": publishOptions.toJson(),
        }

        return self.authPost(session, "publish_task", data)

    def hashes(self, session, scope, table, filter, readOptions):
        data = {"scope": scope, "table": table, "options": readOptions.toJson()}

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "hashes", data)

    def hashCheckpoint(self, session, enable):
        data = {"enable": enable}

        return self.authPost(session, "hash_checkpoint", data)

    def zkProof(self, session, scope, table, gadget, params, fields, filter, zkOptions):
        data = {
            "scope": scope,
            "table": table,
            "gadget": gadget,
            "params": params,
            "fields": fields if isinstance(fields, str) else json.dumps(fields),
            "options": zkOptions.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "zk_proof", data)

    def zkDataProof(self, session, gadget, params, values, zkOptions):
        data = {
            "gadget": gadget,
            "params": params,
            "values": values if isinstance(values, str) else json.dumps(values),
            "options": zkOptions.toJson(),
        }

        return self.authPost(session, "zk_data_proof", data)

    def verifyZkProof(self, session, proof, gadget, params, commitment, nGenerators):
        data = {
            "proof": proof,
            "gadget": gadget,
            "params": params,
            "commitment": commitment,
            "nGenerators": nGenerators,
        }

        return self.authPost(session, "verify_zk_proof", data)

    def taskLineage(self, session, taskId):
        data = {"taskId": taskId}

        return self.authPost(session, "task_lineage", data)

    def verifyTaskLineage(self, session, lineageData):
        data = {"task_lineage": lineageData}

        return self.authPost(session, "verify_task_lineage", data)

    def taskOutputData(self, session, taskId, options):
        data = {"taskId": taskId, "options": options.toJson()}

        return self.authPost(session, "task_output_data", data)

    def mpc(self, session, scope, table, algo, fields, filter, mpcOptions):
        data = {
            "scope": scope,
            "table": table,
            "algo": algo,
            "fields": fields if isinstance(fields, str) else json.dumps(fields),
            "options": mpcOptions.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "mpc", data)

    def storageProof(self, session, scope, table, filter, challenge, options):
        data = {
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "storage_proof", data)

    def zkStorageProof(self, session, scope, table, filter, challenge, options):
        data = {
            "scope": scope,
            "table": table,
            "challenge": challenge,
            "options": options.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "zk_storage_proof", data)

    def merkleTree(self, session, scope, table, filter, salt, digest, options):
        data = {
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "options": options.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "merkle_tree", data)

    def merkleProof(self, session, scope, table, hash, digest = None):
        data = {
            "scope": scope,
            "table": table,
            "digest": digest,
            "hash": hash
        }

        return self.authPost(session, "merkle_proof", data)

    def zkMerkleTree(
        self, session, scope, table, filter, salt, digest, rounds, seed, options
    ):
        data = {
            "scope": scope,
            "table": table,
            "salt": salt,
            "digest": digest,
            "rounds": rounds,
            "seed": seed,
            "options": options.toJson(),
        }

        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "zk_merkle_tree", data)

    def rootHash(self, session, scope, table):
        data = {"scope": scope, "table": table}

        return self.authPost(session, "root_hash", data)

    def mimcHash(self, session, data, rounds, seed, compress = False):
        pdata = {
            "data": data,
            "rounds": rounds,
            "seed": seed,
            "compress": compress
        }

        return self.authPost(session, "mimc_hash", pdata)

    def proofsLastHash(self, session, scope, table):
        pdata = {
            "scope": scope,
            "table": table
        }

        return self.authPost(session, "proofs_last_hash", pdata)

    def updateProofs(self, session, scope, table):
        pdata = {
            "scope": scope,
            "table": table
        }

        return self.authPost(session, "update_proofs", pdata)

    def verifyMerkleHash(self, session, tree, hash, digest):
        data = {
            "tree": tree,
            "hash": hash,
            "digest": digest
        }

        return self.authPost(session, "verify_merkle_hash", data)

    def compute(self, session, image, computeOptions):
        data = {
            "image": image,
            "options": None if computeOptions is None else computeOptions.toJson(),
        }

        return self.authPost(session, "compute", data)

    def getImage(self, session, image, localOutputFolder, computeOptions):
        data = {
            "imageName": image,
            "image": base58.b58encode(image.encode("ascii")).decode("ascii"),
            "localOutputFolder": localOutputFolder,
            "options": None if computeOptions is None else computeOptions.toJson(),
        }

        return self.authDownload(session, "get_image", data)

    def flearn(self, session, image, flOptions):
        data = {
            "image": image,
            "options": None if flOptions is None else flOptions.toJson(),
        }

        return self.authPost(session, "f_learn", data)

    def splitLearn(self, session, serverImage, clientImage, slOptions):
        data = {
            "serverImage": serverImage,
            "clientImage": clientImage,
            "options": None if slOptions is None else slOptions.toJson(),
        }

        return self.authPost(session, "split_learn", data)

    def balance(self, session, accountAddress, scope, token):
        toSign = (
            session.organization
            + "\n"
            + self.clientPublicKey
            + "\n"
            + accountAddress
            + "\n"
            + scope
            + "\n"
            + token
        )
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "signature": signature,
            "x-iv": iv.hex(),
        }

        return self.authPost(session, "balance", data)

    def transfer(self, session, accountAddress, scope, token, amount):
        toSign = (
            session.organization
            + "\n"
            + self.clientPublicKey
            + "\n"
            + accountAddress
            + "\n"
            + scope
            + "\n"
            + token
            + "\n"
            + str(amount)
        )
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "accountAddress": accountAddress,
            "scope": scope,
            "token": token,
            "amount": amount,
            "signature": signature,
            "x-iv": iv.hex(),
        }

        return self.authPost(session, "transfer", data)

    def call(self, session, contractAddress, scope, fn, data):
        serialized = base64.b64encode(data).decode("ascii")
        toSign = (
            session.organization
            + "\n"
            + self.clientPublicKey
            + "\n"
            + contractAddress
            + "\n"
            + scope
            + "\n"
            + fn
            + "\n"
            + serialized
        )
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "contractAddress": contractAddress,
            "scope": scope,
            "function": fn,
            "data": serialized,
            "signature": signature,
            "x-iv": iv.hex(),
        }

        return self.authPost(session, "call", data)

    def updateFees(self, session, scope, fees):
        toSign = (
            session.organization
            + "\n"
            + self.clientPublicKey
            + "\n"
            + scope
            + "\n"
            + fees
        )
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {"scope": scope, "fees": fees, "signature": signature, "x-iv": iv.hex()}

        return self.authPost(session, "update_fees", data)

    def contractState(self, session, contractAddress, scope):
        toSign = (
            session.organization
            + "\n"
            + self.clientPublicKey
            + "\n"
            + contractAddress
            + "\n"
            + scope
        )
        iv = os.urandom(16)
        signature = self.signString(toSign, iv)

        data = {
            "contractAddress": contractAddress,
            "scope": scope,
            "signature": signature,
            "x-iv": iv.hex(),
        }

        return self.authPost(session, "contract_state", data)

    def getSidechainDetails(self, session):
        data = {}
        return self.authPost(session, "get_sidechain_details", data)

    def getUserDetails(self, session, publicKey):
        data = {"publicKey": publicKey}
        return self.authPost(session, "get_user_details", data)

    def getNodes(self, session):
        data = {}
        return self.authPost(session, "get_nodes", data)

    def getScopes(self, session):
        data = {}
        return self.authPost(session, "get_scopes", data)

    def getTables(self, session, scope):
        data = {"scope": scope}
        return self.authPost(session, "get_tables", data)

    def getNodeConfig(self, session, nodePublicKey):
        data = {"nodePublicKey": nodePublicKey}
        return self.authPost(session, "get_node_config", data)

    def getAccountNotifications(self, session):
        data = {}
        return self.authPost(session, "account_notifications", data)

    def getTableDefinition(self, session, scope, table):
        data = {"scope": scope, "table": table}

        return self.authPost(session, "get_table_definition", data)

    def history(self, session, scope, table, filter, historyOptions):
        data = {"scope": scope, "table": table, "options": historyOptions.toJson()}
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "history", data)

    def writers(self, session, scope, table, filter):
        data = {
            "scope": scope,
            "table": table,
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "writers", data)

    def tasks(self, session, scope, table, filter):
        data = {
            "scope": scope,
            "table": table,
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "tasks", data)

    def lineage(self, session, scope, table, filter):
        data = {
            "scope": scope,
            "table": table,
        }
        if filter is not None:
            data["filter"] = filter.toJson()
        return self.authPost(session, "lineage", data)

    def deployOracle(
        self, session, oracleType, targetBlockchain, source, deployOptions
    ):
        data = {
            "oracleType": oracleType,
            "targetBlockchain": targetBlockchain,
            "source": source,
            "options": None if deployOptions is None else json.dumps(deployOptions),
        }

        return self.authPost(session, "deploy_oracle", data)

    def deployFeed(self, session, image, options):
        data = {
            "image": image,
            "options": None if options is None else json.dumps(options),
        }

        return self.authPost(session, "deploy_feed", data)

    def removeFeed(self, session, feedId):
        data = {"feedId": feedId}

        return self.authPost(session, "remove_feed", data)

    def startFeed(self, session, feedId, options):
        data = {
            "feedId": feedId,
            "options": None if options is None else options.toJson(),
        }

        return self.authPost(session, "start_feed", data)

    def stopFeed(self, session, feedId):
        data = {"feedId": feedId}

        return self.authPost(session, "stop_feed", data)

    def forwardApi(self, session, feedId, params):
        data = {
            "feedId": feedId,
            "params": None if params is None else params if isinstance(params, str) else json.dumps(params)
        }

        return self.authPost(session, "forward_api", data)

    def uploadApi(self, session, params):
        data = {
            "params": None if params is None else params if isinstance(params, str) else json.dumps(params)
        }

        return self.authPost(session, "upload_api", data)

    def heGetInputs(self, session, datasources, args):
        data = {}
        if datasources is not None:
            data["datasources"] = json.dumps(datasources)
        if args is not None:
            data["args"] = args if isinstance(args, str) else json.dumps(args)
        return self.authPost(session, "he_get_inputs", data)

    def heGetOutputs(self, session, encoded, args):
        data = {"encoded": encoded}
        if args is not None:
            data["args"] = args if isinstance(args, str) else json.dumps(args)
        return self.authPost(session, "he_get_outputs", data)

    def heEncode(self, session, items):
        data = {"items": items if isinstance(items, str) else json.dumps(items)}
        return self.authPost(session, "he_encode", data)

    def postMessage(self, session, targetInboxKey, message, options):
        data = {
            "targetInboxKey": targetInboxKey,
            "message": message if isinstance(message, str) else json.dumps(message),
            "options": options if isinstance(options, str) else json.dumps(options)
        }
        return self.authPost(session, "post_message", data)

    def pollMessages(self, session, inboxKey, options):
        data = {
            "inboxKey": inboxKey,
            "options": options if isinstance(options, str) else json.dumps(options)
        }
        return self.authPost(session, "poll_messages", data)

    def issueCredentials(self, session, issuer, holder, credentials, options):
        data = {
            "issuer": issuer,
            "holder": holder,
            "credentials": credentials
            if isinstance(credentials, str)
            else json.dumps(credentials),
        }
        if options is not None:
            data["options"] = options.toJson()
        return self.authPost(session, "issue_credentials", data)

    def verifyCredentials(self, session, credentials, options):
        data = {
            "credentials": credentials
            if isinstance(credentials, str)
            else json.dumps(credentials)
        }
        if options is not None:
            data["options"] = options.toJson()
        return self.authPost(session, "verify_credentials", data)

    def createPresentation(self, session, credentials, subject, options):
        data = {
            "credentials": credentials
            if isinstance(credentials, str)
            else json.dumps(credentials),
            "subject": subject,
        }
        if options is not None:
            data["options"] = options.toJson()
        return self.authPost(session, "create_presentation", data)

    def signPresentation(self, session, presentation, domain, challenge, options):
        data = {
            "presentation": presentation
            if isinstance(presentation, str)
            else json.dumps(presentation),
            "domain": domain,
            "challenge": challenge,
        }
        if options is not None:
            data["options"] = options.toJson()
        return self.authPost(session, "sign_presentation", data)

    def verifyPresentation(self, session, presentation, domain, challenge, options):
        data = {
            "presentation": presentation
            if isinstance(presentation, str)
            else json.dumps(presentation),
            "domain": domain,
            "challenge": challenge,
        }
        if options is not None:
            data["options"] = options.toJson()
        return self.authPost(session, "verify_presentation", data)

    def verifyDataSignature(self, session, signer, signature, toSign):
        data = {
            "signer": signer,
            "signature": signature,
            "data": toSign if isinstance(toSign, str) else json.dumps(toSign),
        }
        return self.authPost(session, "verify_data_signature", data)

    def createUserAccount(self, session, organization, account, publicKey, roles):
        data = {
            "targetOrganization": organization,
            "targetAccount": account,
            "publicKey": publicKey,
            "roles": roles,
        }
        return self.authPost(session, "create_user_account", data)

    def resetConfig(self, session):
        data = {}
        return self.authPost(session, "reset_config", data)

    def encrypt(self, call, data, headers):
        toSend = json.dumps(
            {
                "call": call,
                "body": data if isinstance(data, str) else json.dumps(data),
                "headers": headers,
            }
        )

        iv = os.urandom(16)
        encrypted = self.keyExchange.encrypt(
            self.secretKey, toSend, self.apiContext.seed, iv
        )

        request = {
            "x-enc": base64.b64encode(encrypted).decode("ascii"),
            "x-iv": iv.hex(),
            "x-key": self.apiContext.publicKey,
        }

        return request

    def decrypt(self, output):
        reply = json.loads(output["data"])
        data = base64.b64decode(reply["msg"])
        decrypted = self.keyExchange.decrypt(
            self.secretKey, data, self.apiContext.seed, bytes.fromhex(reply["x-iv"])
        )
        output = json.loads(decrypted)

    def buildHeaders(self, session, call, data):
        data["organization"] = session.organization
        data["account"] = session.account

        body = json.dumps(data)
        nonce = str(session.getNonce())
        signature = self.keyExchange.signHTTP(
            session.secret, "/" + self.version + "/" + call, session.apiKey, nonce, body
        )
        headers = {"x-api-key": session.apiKey, "x-nonce": nonce, "x-sig": signature}
        return headers

    def withdraw(self, session, token, amount):
        data = {
            "token": token,
            "amount": amount,
        }
        return self.authPost(session, "withdraw", data)

    def withdrawAuthorize(self, session, token, address):
        toSign = token + "\n" + address
        data = {
            "token": token,
            "address": address,
            "signature": self.apiContext.createEd25519Signature(toSign)
        }
        return self.authPost(session, "withdraw_auth", data)

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
        return self.post("email_auth", encodedData, None)