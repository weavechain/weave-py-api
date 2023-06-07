import os

from weaveapi import weaveapi
from weaveapi.session import Session
from weaveapi.records import *
from weaveapi.options import *
from weaveapi.filter import *

def generate_keys():
    nodeApi = weaveapi.create(None)
    return nodeApi.generateKeys()

def weave_client_config(pub, pvk, node, organization):
    seed = node[node.rindex("/") + 1:]

    cfg = {
        "organization": organization,
        "account": pub,
        "scope": "*",

        "chainClientConfig": {
            "apiVersion" : 1,

            "seed" : seed,
            "privateKey" : pvk,
            "publicKey" : pub,
        }
    }

    if node.startswith("http"):
        idx = node[0:node.rindex("/")].rindex("/") + 1
        items = node[idx:node.rindex("/")].split(":")
        cfg["chainClientConfig"]["http"] = {
            "host": items[0],
            "port": items[1],
            "useHttps": node.startswith("https")
        }
    elif node.startswith("ws"):
        idx = node[0:node.rindex("/")].rindex("/") + 1
        items = node[idx:node.rindex("/"):].split(":")
        cfg["chainClientConfig"]["websocket"] = {
            "host": items[0],
            "port": items[1],
            "useWss": node.startswith("wss")
        }
    return cfg

def connect_weave_api(config_file, credentials = None, no_ping = False):
    SEED = os.environ.get('WEAVE_SEED')

    if config_file is not None:
        if type(config_file) is dict:
            config = config_file
        else:
            with open(config_file) as f:
                config = json.loads(f.read())
                if SEED is not None:
                    config['chainClientConfig']['seed'] = SEED
                if os.environ.get('WEAVE_PUB') is not None:
                    config['chainClientConfig']['publicKey'] = os.environ['WEAVE_PUB']
                if os.environ.get('WEAVE_PVK') is not None:
                    config['chainClientConfig']['privateKey'] = os.environ['WEAVE_PVK']
                #print(config)
    else:
        HOST = 'gw'  # 172.17.0.1/host.docker.internal
        PORT = os.environ['WEAVE_PORT']
        USE_HTTP = os.environ.get('WEAVE_HTTPS') == '0'
        USE_HTTPS = os.environ.get('WEAVE_HTTPS') == '1'
        USE_WS = os.environ.get('WEAVE_WSS') == '0'
        USE_WSS = os.environ.get('WEAVE_WSS') == '1'

        organization = os.environ['WEAVE_ORG']
        account = os.environ['WEAVE_ACCOUNT']

        sessionData = {
            'organization': organization,
            'account': account,
            'scopes': os.environ['WEAVE_SCOPE'],
            'apiKey': os.environ['WEAVE_APIKEY'],
            'secretExpireUTC': os.environ['WEAVE_EXPIRY'],
            'integrityChecks': True if os.environ.get('WEAVE_INTEGRITY') is not None and str(os.environ['WEAVE_INTEGRITY']) == "1" else False
        }
        session = Session(sessionData, os.environ['WEAVE_SECRET'])

        config = {
            'organization': organization,
            'account': account,
            'scope': os.environ['WEAVE_SCOPE'],

            'chainClientConfig': {
                'apiVersion': 1,

                'seed': SEED,
                'publicKey': os.environ['WEAVE_PUB'],
                'privateKey': os.environ['WEAVE_PVK']
            }
        }
        if USE_HTTP or USE_HTTPS:
            config['chainClientConfig']['http'] = {
                'host': HOST,
                'port': PORT,
                'useHttps': USE_HTTPS
            }
        if USE_WS or USE_WSS:
            config['chainClientConfig']['websocket'] = {
                'host': HOST,
                'port': PORT,
                'useWss': USE_WSS
            }

        #print(config)

    organization = config['organization']
    account = config['account']
    scope = config['scope']

    chainConfig = config['chainClientConfig']

    nodeApi = weaveapi.create(chainConfig)
    nodeApi.init()
    if not no_ping:
        print(nodeApi.ping().get())

    if os.environ.get('WEAVE_APIKEY') is not None:
        sessionData = {
            'organization': organization,
            'account': account,
            'scopes': os.environ['WEAVE_SCOPE'],
            'apiKey': os.environ['WEAVE_APIKEY'],
            'secretExpireUTC': os.environ['WEAVE_EXPIRY'],
            'integrityChecks': True if os.environ.get('WEAVE_INTEGRITY') is not None and str(os.environ['WEAVE_INTEGRITY']) == "1" else False
        }
        session = Session(sessionData, os.environ['WEAVE_SECRET'])
    else:
        session = nodeApi.login(organization, account, scope, credentials).get()

    return nodeApi, session

def weave_task_output(nodeApi, session, result, metadata=None):
    records = Records(os.environ['WEAVE_TASKID'], [ Record('OUTPUT', result, metadata) ])
    res = nodeApi.write(session, '.internal_task_params', records, WRITE_DEFAULT).get()
