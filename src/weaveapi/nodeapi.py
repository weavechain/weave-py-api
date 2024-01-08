from .apicontext import ApiContext
from .clientws import ClientWs
from .clienthttp import ClientHttp
from .keys import readKey
from .options import DEFAULT_COMMITMENT, DEFAULT_GENERATORS
from .utils import standardizeRecord
import base58, base64
import json

#TODO: add logging

class NodeApi:
    def __init__(self, config):
        self.config = config

    def init(self):
        cfg = self.config

        self.clientPublicKey = readKey(cfg.get("publicKey"), cfg.get("publicKeyFile"))

        if cfg.get("websocket") is not None:
            self.client = ClientWs(cfg)
        elif cfg.get("http") is not None:
            self.client = ClientHttp(cfg)

        if self.client is not None:
            self.client.init()

    def close(self):
        if self.client is not None:
            self.client.close()

    def version(self):
        return self.client.version()

    def ping(self):
        return self.client.ping()

    def generateKeys(self):
        return ApiContext.generateKeys()

    def getClientPublicKey(self):
        return self.clientPublicKey

    def publicKey(self):
        return self.client.publicKey()

    def sigKey(self):
        return self.client.sigKey()

    def status(self, session):
        return self.client.status(session)

    def login(self, organization, account, scopes, credentials = None):
        return self.client.login(organization, account, scopes, credentials)

    def logout(self, session):
        return self.client.logout(session)

    def checkSession(self, session, credentials = None):
        if session is not None and session.nearExpiry():
            return self.login(session.organization, session.account, session.scopes, credentials)
        else:
            return session

    def terms(self, session, options):
        return self.client.terms(session, options)

    def createTable(self, session, scope, table, createOptions):
        return self.client.createTable(session, scope, table, createOptions)

    def dropTable(self, session, scope, table):
        return self.client.dropTable(session, scope, table)

    def write(self, session, scope, records, writeOptions):
        return self.client.write(session, scope, records, writeOptions)

    def read(self, session, scope, table, filter, readOptions):
        return self.client.read(session, scope, table, filter, readOptions)

    def readStream(self, session, scope, table, filter, readOptions, outputFolder, outputFile):
        return self.client.readStream(session, scope, table, filter, readOptions, outputFolder, outputFile)

    def readReceipts(self, session):
        return self.client.readReceipts(session)

    def count(self, session, scope, table, filter, readOptions):
        return self.client.count(session, scope, table, filter, readOptions)

    def delete(self, session, scope, table, filter, deleteOptions):
        return self.client.delete(session, scope, table, filter, deleteOptions)

    def hashes(self, session, scope, table, filter, readOptions):
        return self.client.hashes(session, scope, table, filter, readOptions)

    def hashCheckpoint(self, session, enable):
        return self.client.hashCheckpoint(session, enable)

    def downloadTable(self, session, scope, table, filter, format, readOptions):
        return self.client.downloadTable(session, scope, table, filter, format, readOptions)

    def publishDataset(self, session,
                       did, name, description, license, metadata, weave, fullDescription, logo, category,
                       scope, table, filter, format, price, token, pageorder, publishOptions):
        return self.client.publishDataset(session, did, name, description, license, metadata, weave, fullDescription, logo, category, scope, table, filter, format, price, token, pageorder, publishOptions)

    def enableProduct(self, session, did, productType, active):
        return self.client.enableProduct(session, did, productType, active)

    def downloadDataset(self, session, did, readOptions):
        return self.client.downloadDataset(session, did, readOptions)

    def publishTask(self, session,
                    did, name, description, license, metadata, weave, fullDescription, logo, category,
                    task, price, token, pageorder, publishOptions):
        return self.client.publishTask(session, did, name, description, license, metadata, weave, fullDescription, logo, category, task, price, token, pageorder, publishOptions)

    def runTask(self, session, did, computeOptions):
        return self.client.runTask(session, did, computeOptions)

    def subscribe(self, session, scope, table, filter, subscribeOptions, updateHandler):
        return self.client.subscribe(session, scope, table, filter, subscribeOptions, updateHandler)

    def unsubscribe(self, session, subscriptionId):
        return self.client.unsubscribe(session, subscriptionId)

    def compute(self, session, image, computeOptions):
        return self.client.compute(session, image, computeOptions)
    
    def getImage(self, session, image, localOutputFolder, computeOptions):
        return self.client.getImage(session, image, localOutputFolder, computeOptions)

    def flearn(self, session, image, flOptions):
        return self.client.flearn(session, image, flOptions)
    
    def splitLearn(self, session, serverImage, clientImage, slOptions):
        return self.client.splitLearn(session, serverImage, clientImage, slOptions)

    def forwardApi(self, session, feedId, params):
        return self.client.forwardApi(session, feedId, params)

    def uploadApi(self, session, params):
        return self.client.uploadApi(session, params)

    def heGetInputs(self, session, datasources, args):
        return self.client.heGetInputs(session, datasources, args)

    def heGetOutputs(self, session, encoded, args):
        return self.client.heGetOutputs(session, encoded, args)

    def heEncode(self, session, items):
        return self.client.heEncode(session, items)

    def mpc(self, session, scope, table, algo, fields, filter, mpcOptions):
        return self.client.mpc(session, scope, table, algo, fields, filter, mpcOptions)

    def storageProof(self, session, scope, table, filter, challenge, options):
        return self.client.storageProof(session, scope, table, filter, challenge, options)

    def zkStorageProof(self, session, scope, table, filter, challenge, options):
        return self.client.zkStorageProof(session, scope, table, filter, challenge, options)

    def merkleTree(self, session, scope, table, filter, salt, digest, options):
        return self.client.merkleTree(session, scope, table, filter, salt, digest, options)

    def merkleProof(self, session, scope, table, hash, digest = None):
        return self.client.merkleProof(session, scope, table, hash, digest)

    def rootHash(self, session, scope, table):
        return self.client.rootHash(session, scope, table)

    def zkMerkleTree(self, session, scope, table, filter, salt, digest, rounds, seed, options):
        return self.client.zkMerkleTree(session, scope, table, filter, salt, digest, rounds, seed, options)

    def mimcHash(self, session, data, rounds, seed, compress = False):
        return self.client.mimcHash(session, data, rounds, seed, compress)

    def proofsLastHash(self, session, scope, table):
        return self.client.proofsLastHash(session, scope, table)

    def updateProofs(self, session, scope, table):
        return self.client.updateProofs(session, scope, table)

    def verifyMerkleHash(self, session, tree, hash, digest = None):
        #using remote function for now, could be local
        return self.client.verifyMerkleHash(session, tree, hash, digest)

    def hashRecord(self, row, salt, digest = None):
        #layout = self.client.getLayout(session, scope, table)
        #record = standardizeRecord(row, layout)
        data = row if isinstance(row, str) else json.dumps(row, separators=(',', ':'), ensure_ascii=False)
        enc = self.client.keyExchange.signRequest(bytes(salt, encoding='utf-8') if salt is not None else None, data, digest)
        return base58.b58encode(base64.b64decode(enc)).decode('utf-8')

    def sign(self, data):
        return self.client.apiContext.createEd25519Signature(data)

    def verifyKeySignature(self, publicKey, signature, data):
        return self.client.apiContext.verifyEd25519Signature(publicKey, signature, data)

    def zkProof(self, session, scope, table, gadget, params, fields, filter, zkOptions):
        return self.client.zkProof(session, scope, table, gadget, params, fields, filter, zkOptions)

    def zkDataProof(self, session, gadget, params, values, zkOptions):
        return self.client.zkDataProof(session, gadget, params, values, zkOptions)

    def verifyZkProof(self, session, proof, gadget, params, commitment = DEFAULT_COMMITMENT, nGenerators = DEFAULT_GENERATORS):
        return self.client.verifyZkProof(session, proof, gadget, params, commitment, nGenerators)

    def taskLineage(self, session, taskId):
        return self.client.taskLineage(session, taskId)

    def verifyTaskLineage(self, session, lineageData):
        return self.client.verifyTaskLineage(session, lineageData)

    def taskOutputData(self, session, taskId, options):
        return self.client.taskOutputData(session, taskId, options)

    def history(self, session, scope, table, filter, historyOptions):
        return self.client.history(session, scope, table, filter, historyOptions)

    def writers(self, session, scope, table, filter):
        return self.client.writers(session, scope, table, filter)

    def tasks(self, session, scope, table, filter):
        return self.client.tasks(session, scope, table, filter)

    def lineage(self, session, scope, table, filter):
        return self.client.lineage(session, scope, table, filter)

    def deployOracle(self, session, oracleType, targetBlockchain, source, deployOptions):
        return self.client.deployOracle(session, oracleType, targetBlockchain, source, deployOptions)

    def deployFeed(self, session, image, options):
        return self.client.deployOracle(session, image, options)

    def removeFeed(self, session, feedId):
        return self.client.removeFeed(session, feedId)

    def startFeed(self, session, feedId, options):
        return self.client.startFeed(session, feedId, options)

    def stopFeed(self, session, feedId):
        return self.client.stopFeed(session, feedId)

    def issueCredentials(self, session, issuer, holder, credentials, options):
        return self.client.issueCredentials(session, issuer, holder, credentials, options)

    def verifyCredentials(self, session, credentials, options):
        return self.client.verifyCredentials(session, credentials, options)

    def createPresentation(self, session, credentials, subject, options):
        return self.client.createPresentation(session, credentials, subject, options)

    def signPresentation(self, session, presentation, domain, challenge, options):
        return self.client.signPresentation(session, presentation, domain, challenge, options)

    def verifyDataSignature(self, session, signer, signature, toSign):
        return self.client.verifyDataSignature(session, signer, signature, toSign)

    def verifyLineageSignature(self, signature, inputHash, computeHash, paramsHash, data):
        try:
            pubKey = self.client.apiContext.deserializePublic(self.client.serverSigKey)
            toSign = ('' if inputHash is None else inputHash + '\n') + \
                     ('' if computeHash is None else computeHash + '\n') + \
                     ('' if paramsHash is None else paramsHash + '\n') + \
                     data
            pubKey.verify(base58.b58decode(signature), toSign.encode('utf-8'))
            return True
        except:
            return False

    def verifySignature(self, signature, data):
        try:
            pubKey = self.client.apiContext.deserializePublic(self.client.serverSigKey)
            pubKey.verify(base58.b58decode(signature), data.encode('utf-8'))
            return True
        except:
            return False

    def verifyHeaderSignature(self, signature, data):
        try:
            pubKey = self.client.apiContext.deserializePublic(self.client.serverSigKey)
            pubKey.verify(base58.b58decode(signature), base58.b58decode(data))
            return True
        except:
            return False

    def verifyPresentation(self, session, presentation, domain, challenge, options):
        return self.client.verifyPresentation(session, presentation, domain, challenge, options)

    def postMessage(self, session, targetInboxKey, message, options):
        return self.client.postMessage(session, targetInboxKey, message, options)

    def pollMessages(self, session, inboxKey, options):
        return self.client.pollMessages(session, inboxKey, options)


    def getSidechainDetails(self, session):
        return self.client.getSidechainDetails(session)

    def getUserDetails(self, session, publicKey):
        return self.client.getUserDetails(session, publicKey)

    def getNodes(self, session):
        return self.client.getNodes(session)

    def getScopes(self, session):
        return self.client.getScopes(session)

    def getTables(self, session, scope):
        return self.client.getTables(session, scope)

    def getTableDefinition(self, session, scope, table):
        return self.client.getTableDefinition(session, scope, table)

    def getNodeConfig(self, session, nodePublicKey):
        return self.client.getNodeConfig(session, nodePublicKey)

    def getAccountNotifications(self, session):
        return self.client.getAccountNotifications(session)

    def updateLayout(self, session, scope, table, layout):
        return self.client.updateLayout(session, scope, table, layout)

    def updateConfig(self, session, path, values):
        return self.client.updateConfig(session, path, values)

    def grantRole(self, session, account, roles):
        return self.client.grantRole(session, account, roles)

    def balance(self, session, accountAddress, scope, token):
        return self.client.balance(session, accountAddress, scope, token)

    def transfer(self, session, accountAddress, scope, token, amount):
        return self.client.transfer(session, accountAddress, scope, token, amount)

    def call(self, session, contractAddress, scope, fn, data):
        return self.client.call(session, contractAddress, scope, fn, data)

    def updateFees(self, session, scope, fees):
        return self.client.updateFees(session, scope, fees)

    def contractState(self, session, contractAddress, scope):
        return self.client.contractState(session, contractAddress, scope)

    def createUserAccount(self, session, organization, account, publicKey, roles):
        return self.client.createUserAccount(session, organization, account, publicKey, roles)

    def resetConfig(self, session):
        return self.client.resetConfig(session)

    def withdraw(self, session, token, amount):
        return self.client.withdraw(session, token, amount)

    def withdrawAuthorize(self, session, token, address):
        return self.client.withdrawAuthorize(session, token, address)

    def emailAuth(self, org, clientPubKey, targetWebUrl, email):
        return self.client.emailAuth(org, clientPubKey, targetWebUrl, email)