import json

class TermsOptions:
    def __init__(self, agreeTerms = False, agreePrivacyPolicy = False):
        self.agreeTerms = agreeTerms
        self.agreePrivacyPolicy = agreePrivacyPolicy

    def toJson(self):
        return json.dumps({
            "agreeTerms": self.agreeTerms,
            "agreePrivacyPolicy": self.agreePrivacyPolicy
        })

TERMS_AGREE = TermsOptions(True, True)
TERMS_DISAGREE = TermsOptions(False, False)

DEFAULT_CREATE_TIMEOUT_SEC = 300

class CreateOptions:
    def __init__(self, failIfExists, replicate = True, layout = None, createTimeoutSec = DEFAULT_CREATE_TIMEOUT_SEC):
        self.failIfExists = failIfExists
        self.replicate = replicate
        self.layout = layout
        self.createTimeoutSec = createTimeoutSec

    def toJson(self):
        return json.dumps({
            "failIfExists": self.failIfExists,
            "replicate": self.replicate,
            "layout": self.layout,
            "createTimeoutSec": self.createTimeoutSec
        })

CREATE_DEFAULT = CreateOptions(True, True, None, DEFAULT_CREATE_TIMEOUT_SEC)
CREATE_FAILSAFE = CreateOptions(False, True, None, DEFAULT_CREATE_TIMEOUT_SEC)

class DropOptions:
    def __init__(self, failIfNotExists, replicate = True, dropTimeoutSec = DEFAULT_CREATE_TIMEOUT_SEC):
        self.failIfNotExists = failIfNotExists
        self.replicate = replicate
        self.dropTimeoutSec = dropTimeoutSec

    def toJson(self):
        return json.dumps({
            "failIfNotExists": self.failIfNotExists,
            "replicate": self.replicate,
            "dropTimeoutSec": self.dropTimeoutSec
        })

DROP_DEFAULT = DropOptions(True, True, DEFAULT_CREATE_TIMEOUT_SEC)
DROP_FAILSAFE = CreateOptions(False, True, DEFAULT_CREATE_TIMEOUT_SEC)

class DeleteOptions:
    def __init__(self, allowDistribute, correlationUuid, thresholdMultisigContext = None):
        self.allowDistribute = allowDistribute
        self.correlationUuid = correlationUuid
        self.thresholdMultisigContext = thresholdMultisigContext

    def toJson(self):
        return json.dumps({
            "allowDistribute" : self.allowDistribute,
            "correlationUuid" : self.correlationUuid,
            "thresholdMultisigContext" : self.thresholdMultisigContext
        })

DELETE_DEFAULT = DeleteOptions(True, None, None)

class HistoryOptions:
    def __init__(self, operationTypes):
        self.operationTypes = operationTypes

    def toJson(self):
        return json.dumps({
            "operationTypes": self.operationTypes
        })

    @staticmethod
    def fromJson(json):
        return HistoryOptions(json["operationTypes"])

HISTORY_DEFAULT = HistoryOptions(["read", "delete", "write"])

class ReadOptions:
    def __init__(self, verifyHash, readTimeoutSec, peersConsensus = 0, enableMux = False, getBatchHashes = False):
        self.verifyHash = verifyHash
        self.readTimeoutSec = readTimeoutSec
        self.peersConsensus = peersConsensus
        self.enableMux = enableMux
        self.getBatchHashes = getBatchHashes;

    def toJson(self):
        return json.dumps({
            "verifyHash": self.verifyHash,
            "readTimeoutSec": self.readTimeoutSec,
            "peersConsensus": self.peersConsensus,
            "enableMux": self.enableMux,
            "getBatchHashes": self.getBatchHashes
        })

    @staticmethod
    def fromJson(json):
        return ReadOptions(
            json["verifyHash"],
            json["readTimeoutSec"],
            json["peersConsensus"],
            json["enableMux"],
            json["getBatchHashes"]
        )

DEFAULT_READ_TIMEOUT_SEC = 300

ALL_ACTIVE = 2147483647

READ_DEFAULT = ReadOptions(True, DEFAULT_READ_TIMEOUT_SEC, 0, False, False)
READ_DEFAULT_NO_CHAIN = ReadOptions(False, DEFAULT_READ_TIMEOUT_SEC, 0, False, False)
READ_DEFAULT_MUX = ReadOptions(True, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE, True, False)
READ_DEFAULT_MUX_NO_CHAIN = ReadOptions(False, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE, True, False)


ALL_ACTIVE_NODES = [ "*" ]

class MPCOptions:
    def __init__(self, verifyHash, readTimeoutSec, sources = ALL_ACTIVE_NODES):
        self.verifyHash = verifyHash
        self.readTimeoutSec = readTimeoutSec
        self.sources = sources

    def toJson(self):
        return json.dumps({
            "verifyHash": self.verifyHash,
            "readTimeoutSec": self.readTimeoutSec,
            "sources": self.sources
        })

    @staticmethod
    def fromJson(json):
        return MPCOptions(
            json["verifyHash"],
            json["readTimeoutSec"],
            json["sources"]
        )

MPC_DEFAULT = MPCOptions(True, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES)
MPC_DEFAULT_NO_CHAIN = MPCOptions(False, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES)


DEFAULT_GENERATORS = 128
DEFAULT_COMMITMENT = "GGumV86X6FZzHRo8bLvbW2LJ3PZ45EqRPWeogP8ufcm3"

class ZKOptions:
    def __init__(self, verifyHash, readTimeoutSec, sources = ALL_ACTIVE_NODES, generators = DEFAULT_GENERATORS, commitment = DEFAULT_COMMITMENT):
        self.verifyHash = verifyHash
        self.readTimeoutSec = readTimeoutSec
        self.sources = sources
        self.generators = generators
        self.commitment = commitment

    def toJson(self):
        return json.dumps({
            "verifyHash": self.verifyHash,
            "readTimeoutSec": self.readTimeoutSec,
            "sources": self.sources,
            "generators": self.generators,
            "commitment": self.commitment
        })

    @staticmethod
    def fromJson(json):
        return ZKOptions(
            json["verifyHash"],
            json["readTimeoutSec"],
            json["sources"],
            json["generators"],
            json["commitment"]
        )

ZK_DEFAULT = ZKOptions(True, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT)
ZK_DEFAULT_NO_CHAIN = ZKOptions(False, DEFAULT_READ_TIMEOUT_SEC, ALL_ACTIVE_NODES, DEFAULT_GENERATORS, DEFAULT_COMMITMENT)

class SubscribeOptions:
    def __init__(self, verifyHash, initialSnapshot, readTimeoutSec, externalUpdates,batchingOptions):
        self.verifyHash = verifyHash
        self.initialSnapshot = initialSnapshot
        self.readTimeoutSec = readTimeoutSec
        self.externalUpdates = externalUpdates
        self.batchingOptions = batchingOptions

    def toJson(self):
        return json.dumps({
            "verifyHash": self.verifyHash,
            "initialSnapshot": self.initialSnapshot,
            "readTimeoutSec": self.readTimeoutSec,
            "externalUpdates": self.externalUpdates,
            "batchingOptions": self.batchingOptions,
        })

SUBSCRIBE_DEFAULT = SubscribeOptions(True, True, DEFAULT_READ_TIMEOUT_SEC, False, None)

class WriteOptions:
    def __init__(self, guaranteed, minAcks, inMemoryAcks, minHashAcks, writeTimeoutSec, allowDistribute, signOnChain, syncSigning):
        self.guaranteed = guaranteed
        self.minAcks = minAcks
        self.inMemoryAcks = inMemoryAcks
        self.minHashAcks = minHashAcks
        self.writeTimeoutSec = writeTimeoutSec
        self.allowDistribute = allowDistribute
        self.signOnChain = signOnChain
        self.syncSigning = syncSigning

    def toJson(self):
        return json.dumps({
            "guaranteed": self.guaranteed,
            "minAcks": self.minAcks,
            "inMemoryAcks": self.inMemoryAcks,
            "minHashAcks": self.minHashAcks,
            "writeTimeoutSec": self.writeTimeoutSec,
            "allowDistribute": self.allowDistribute,
            "signOnChain": self.signOnChain,
            "syncSigning": self.syncSigning
        })

DEFAULT_GUARANTEED_DELIVERY = True
DEFAULT_MIN_ACKS = 1
DEFAULT_MEMORY_ACKS = False
DEFAULT_HASH_ACKS = 1
DEFAULT_WRITE_TIMEOUT_SEC = 300

WRITE_DEFAULT = WriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        DEFAULT_HASH_ACKS,
        DEFAULT_WRITE_TIMEOUT_SEC,
        True,
        True,
        False
)

WRITE_DEFAULT_ASYNC = WriteOptions(
        False,
        DEFAULT_MIN_ACKS,
        True,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        True,
        True,
        False
)
WRITE_DEFAULT_NO_CHAIN = WriteOptions(
        DEFAULT_GUARANTEED_DELIVERY,
        DEFAULT_MIN_ACKS,
        DEFAULT_MEMORY_ACKS,
        0,
        DEFAULT_WRITE_TIMEOUT_SEC,
        True,
        False,
        False
)

class ComputeOptions:
    def __init__(self, sync, timeoutSec, peersConsensus, scopes, params):
        self.sync = sync
        self.timeoutSec = timeoutSec
        self.peersConsensus = peersConsensus
        self.scopes = scopes
        self.params = params

    def toJson(self):
        return json.dumps({
            "sync": self.sync,
            "timeoutSec": self.timeoutSec,
            "peersConsensus": self.peersConsensus,
            "scopes": self.scopes,
            "params": None if self.params is None else json.dumps(self.params)
        })

    @staticmethod
    def fromJson(json):
        return ComputeOptions(
            json["sync"],
            json["timeoutSec"],
            json["peersConsensus"],
            json["scopes"],
            json["params"]
        )

DEFAULT_COMPUTE_TIMEOUT_SEC = 300

ALL_ACTIVE_PEERS = 2147483647

COMPUTE_DEFAULT = ComputeOptions(True, DEFAULT_COMPUTE_TIMEOUT_SEC, 0, None, None)

class FLOptions:
    def __init__(self, sync, timeoutSec, peersConsensus, scopes, params):
        self.sync = sync
        self.timeoutSec = timeoutSec
        self.peersConsensus = peersConsensus
        self.scopes = scopes
        self.params = params

    def toJson(self):
        return json.dumps({
            "sync": self.sync,
            "timeoutSec": self.timeoutSec,
            "peersConsensus": self.peersConsensus,
            "scopes": self.scopes,
            "params": None if self.params is None else json.dumps(self.params)
        })

    @staticmethod
    def fromJson(json):
        return FLOptions(
            json["sync"],
            json["timeoutSec"],
            json["peersConsensus"],
            json["scopes"],
            json["params"]
        )

FL_DEFAULT = FLOptions(True, DEFAULT_COMPUTE_TIMEOUT_SEC, 0, None, None)

class SLOptions:
    def __init__(self, sync, timeoutSec, minParticipants, scopes, sources, params):
        self.sync = sync
        self.timeoutSec = timeoutSec
        self.minParticipants = minParticipants
        self.scopes = scopes
        self.sources = sources
        self.params = params

    def toJson(self):
        return json.dumps({
            "sync": self.sync,
            "timeoutSec": self.timeoutSec,
            "minParticipants": self.minParticipants,
            "scopes": self.scopes,
            "sources": self.sources,
            "params": None if self.params is None else json.dumps(self.params)
        })

    @staticmethod
    def fromJson(json):
        return FLOptions(
            json["sync"],
            json["timeoutSec"],
            json["minParticipants"],
            json["scopes"],
            json["sources"],
            json["params"]
        )

SL_DEFAULT = SLOptions(True, DEFAULT_COMPUTE_TIMEOUT_SEC, 0, None, None, None)

class CredentialsOptions:
    def __init__(self, opTimeoutSec, proofType, expirationTimestampGMT):
        self.opTimeoutSec = opTimeoutSec
        self.proofType = proofType
        self.expirationTimestampGMT = expirationTimestampGMT

    def toJson(self):
        return json.dumps({
            "opTimeoutSec": self.opTimeoutSec,
            "proofType": self.proofType,
            "expirationTimestampGMT": self.expirationTimestampGMT
        })

    @staticmethod
    def fromJson(json):
        return CredentialsOptions(
            json["opTimeoutSec"],
            json["proofType"],
            json["expirationTimestampGMT"]
        )

VC_DEFAULT = CredentialsOptions(DEFAULT_READ_TIMEOUT_SEC, "json-ld", None)

class PublishOptions:
    def __init__(self, type, rollingUnit, rollingCount, verifyHash, readTimeoutSec, peersConsensus = 0, enableMux = False):
        self.type = type
        self.rollingUnit = rollingUnit
        self.rollingCount = rollingCount
        self.verifyHash = verifyHash
        self.readTimeoutSec = readTimeoutSec
        self.peersConsensus = peersConsensus
        self.enableMux = enableMux

    def toJson(self):
        return json.dumps({
            "type": self.type,
            "rollingUnit": self.rollingUnit,
            "rollingCount": self.rollingCount,
            "verifyHash": self.verifyHash,
            "readTimeoutSec": self.readTimeoutSec,
            "peersConsensus": self.peersConsensus,
            "enableMux": self.enableMux
        })

    @staticmethod
    def fromJson(json):
        return PublishOptions(
            json["type"],
            json["rollingUnit"],
            json["rollingCount"],
            json["verifyHash"],
            json["readTimeoutSec"],
            json["peersConsensus"],
            json["enableMux"]
        )

DEFAULT_PUBLISH_TIMEOUT_SEC = 300

PUBLISH_DEFAULT = PublishOptions("snapshot", None, None, True, DEFAULT_READ_TIMEOUT_SEC, 0, False)

class PublishTaskOptions:
    def __init__(self, computeTimeoutSec, params = None, allowCustomParams = False):
        self.computeTimeoutSec = computeTimeoutSec
        self.params = params
        self.allowCustomParams = allowCustomParams

    def toJson(self):
        return json.dumps({
            "computeTimeoutSec": self.computeTimeoutSec,
            "params": self.params,
            "allowCustomParams": self.allowCustomParams
        })

    @staticmethod
    def fromJson(json):
        return PublishOptions(
            json["computeTimeoutSec"],
            json["params"],
            json["allowCustomParams"]
        )

PUBLISH_TASK_DEFAULT = PublishTaskOptions(DEFAULT_COMPUTE_TIMEOUT_SEC, None, False)