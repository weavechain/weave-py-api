import json

class Filter:
    def __init__(self, op, order, limit, collapsing = None, columns = None, postFilterOp = None):
        self.op = op
        self.order = order #dict() preserves insertion order
        self.limit = limit
        self.collapsing = collapsing
        self.columns = columns
        self.postFilterOp = postFilterOp

    def toJson(self):
        return json.dumps({
            "op": None if self.op is None else self.op if isinstance(self.op, str) or isinstance(self.op, dict) else self.op.toDict(),
            "order": self.order,
            "limit": self.limit,
            "collapsing": self.collapsing,
            "columns": self.columns,
            "postFilterOp": self.postFilterOp
        })

    @staticmethod
    def fromJson(json):
        return Filter(
            json["op"],
            json["order"],
            json["limit"],
            json.get("collapsing"),
            json.get("columns"),
            json.get("postFilterOp")
        )


class FilterOp:
    def __init__(self, operation, left, right, value):
        self.operation = operation
        self.left = left
        self.right = right
        self.value = value

    @staticmethod
    def field(field):
        return FilterOp("field", None, None, field)

    @staticmethod
    def value(value):
        return FilterOp("value", None, None, value)

    @staticmethod
    def eq(field, value):
        return FilterOp("eq", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def neq(field, value):
        return FilterOp("neq", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def isin(field, values):
        return FilterOp("in", field if isinstance(field, FilterOp) else FilterOp.field(field), values if isinstance(values, FilterOp) else FilterOp.value(values), None)

    @staticmethod
    def notin(field, values):
        return FilterOp("notin", field if isinstance(field, FilterOp) else FilterOp.field(field), values if isinstance(values, FilterOp) else FilterOp.value(values), None)

    @staticmethod
    def gt(field, value):
        return FilterOp("gt", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def gte(field, value):
        return FilterOp("gte", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def lt(field, value):
        return FilterOp("lt", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def lte(field, value):
        return FilterOp("lte", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    @staticmethod
    def opand(expr1, expr2):
        return FilterOp("and", expr1, expr2, None)

    @staticmethod
    def opor(expr1, expr2):
        return FilterOp("or", expr1, expr2, None)

    @staticmethod
    def contains(field, value):
        return FilterOp("contains", field if isinstance(field, FilterOp) else FilterOp.field(field), value if isinstance(value, FilterOp) else FilterOp.value(value), None)

    def toJson(self):
        return json.dumps(self, default=lambda o: o.__dict__)

    def toDict(self):
        return json.loads(json.dumps(self, default=lambda o: o.__dict__))

    @staticmethod
    def fromJson(json):
        return FilterOp(
            json["operation"],
            json["left"],
            json["right"],
            json["value"]
        )