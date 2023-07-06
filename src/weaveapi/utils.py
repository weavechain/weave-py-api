import socket, struct, os
import json
import traceback
from .records import *

def get_default_gateway():
    if os.environ.get('WEAVE_HOST') is not None:
        return os.environ['WEAVE_HOST']
    if os.environ.get('WEAVE_HOST_OS') is not None and os.environ.get('WEAVE_HOST_OS') == "win":
        return "host.docker.internal"

    try:
        with open("/proc/net/route") as fh: #linux
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
    except:
        ip = socket.gethostbyname(socket.gethostname())
        idx = ip.rfind('.')
        return ip[0:idx + 1] + "1" if ip.startsWith("172.") else "172.17.0.1" #fallback to the most common configuration

def is_docker():
    path = '/proc/self/cgroup'
    return os.path.exists('/.dockerenv') or os.path.isfile(path) and any('docker' in line for line in open(path))

def parse_host(host):
    return host if host != "gw" or not is_docker() else get_default_gateway()

def convert(obj, type):
    try:
        if obj is None:
            return None
        elif type == "LONG" or type == "TIMESTAMP":
            return int(obj)
        elif type == "DOUBLE":
            return float(obj)
        else:
            return str(obj)
    except:
        return obj

def standardizeRecord(record, layout):
    rec = record
    if layout is not None:
        rec = record.records if isinstance(record, Records) else record
        if isinstance(rec, Record):
            rec = [ rec.id, rec.data, rec.metadata ]
        for i in range(len(layout)):
            if i < len(rec):
                conv = convert(rec[i], layout[i]["type"])
                if conv is not None and isinstance(conv, float):
                    cstr = str(conv)
                    if len(cstr) > 2 and cstr[-2:] == ".0":
                        conv = int(conv)
                rec[i] = conv
            else:
                rec.append(None)
    return record if isinstance(record, Records) else rec

def integritySignature(clientPublicKey, session, scope, records, tableDefinition, hashFn, seedHex, signFn):
    if records is not None and records.records is not None:
        try:
            idColumn = int(tableDefinition["idColumnIndex"]) if tableDefinition is not None else None
            layout = tableDefinition["columns"] if tableDefinition is not None else None

            salt = bytes(seedHex, encoding='utf-8')

            idBuffer = ""
            hashBuffer = ""
            first = True
            for r in records.records:
                record = standardizeRecord(r, layout)
                data = record.toJson() if isinstance(record, Record) else json.dumps(record, separators=(',', ':'), ensure_ascii=False)
                hash = hashFn(salt, data)

                if first:
                    first = False
                else:
                    idBuffer += " "
                    hashBuffer += "\n"
                idBuffer += "null" if idColumn is None or record[idColumn] is None else str(record[idColumn])
                hashBuffer += hash

            toSign = idBuffer + "\n" + hashBuffer
            recordsHash = hashFn(salt, toSign)

            key = scope + ":" + records.table
            prevRecordsData = session.prevRecordsData.get(key)
            count = 1 if prevRecordsData is None else prevRecordsData["count"]
            integrityCheck = {
                "recordsHash": recordsHash,
                "count": str(count),
                "pubKey": clientPublicKey
            }

            if prevRecordsData is not None:
                integrityCheck["prevRecordsHash"] = prevRecordsData["hash"]
            session.prevRecordsData[key] = { "hash": recordsHash, "count": count + 1 }

            serialization = json.dumps(integrityCheck, sort_keys=True, separators=(',', ':'))
            integrityCheck["sig"] = signFn(serialization)

            return [ { "sig": integrityCheck } ]
        except:
            print(traceback.format_exc())
            return None
    else:
        return None