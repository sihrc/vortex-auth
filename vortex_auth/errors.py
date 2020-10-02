from vortex.errors import VortexException


class LoginRequired(VortexException):
    def __init__(self):
        super().__init__("Login is required to access this", code=401)


class InvalidRefreshToken(VortexException):
    def __init__(self):
        super().__init__("Expired Token. Please logout and log back in", code=401)


class InvalidToken(VortexException):
    def __init__(self):
        super().__init__("Invalid Token", code=401)


class ExpiredToken(VortexException):
    def __init__(self):
        super().__init__("Expired Token. Please go through refresh flow", code=401)
