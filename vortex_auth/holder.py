class Auth(object):
    def __init__(self, values=None):
        self.values = values or {}

    def __setattr__(self, name, value):
        if name != "values":
            self.values[name] = value
        else:
            super().__setattr__(name, value)

    def __getattribute__(self, key):
        if key != "values" and key in self.values:
            return self.values[key]
        try:
            return super().__getattribute__(key)
        except AttributeError:
            return None

    def __str__(self):
        return str(self.values)
