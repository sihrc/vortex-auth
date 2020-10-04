class Auth(object):
    def __init__(self, values=None):
        self.values = values or {}

    def __getattribute__(self, key):
        if key in self.values:
            return self.values[key]
        return super().__getattribute__(key)

    def __str__(self):
        return str(self.values)
