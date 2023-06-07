import json

class Records:
    def __init__(self, table, records):
        self.table = table
        self.records = records
        self.integrity = None

    def get(self, index):
        return self.records[index]

    def toJson(self):
        data = {
            "table": self.table,
            "items": [ r.toArray() if isinstance(r, Record) else r for r in self.records ]
        }
        if self.integrity is not None:
            data["integrity"] = self.integrity
        return json.dumps(data, separators=(',', ':'))

class Record:
    def __init__(self, id, data, metadata):
        self.id = id
        self.data = data
        self.metadata = metadata

    def toArray(self):
        return [
            self.id,
            self.data,
            self.metadata
        ]

    def toJson(self):
        return json.dumps([
            self.id,
            self.data,
            self.metadata
        ], separators=(',', ':'))