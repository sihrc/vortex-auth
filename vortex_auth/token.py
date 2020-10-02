import jwt
import datetime

from .config import Configuration
from .errors import InvalidRefreshToken, InvalidToken, ExpiredToken


def decode_token(self, token, audience=()):
    try:
        data = jwt.decode(
            token,
            Configuration.auth_secret,
            algorithm="HS256",
            audience=Configuration.audience + audience,
        )
    except (jwt.DecodeError, jwt.InvalidAudienceError):
        raise InvalidToken()
    except jwt.ExpiredSignatureError:
        raise ExpiredToken()
    else:
        return {
            key[5:]: value for key, value in data.items() if key.startswith("user_")
        }


def generate_refresh_token(payload):
    """
    No option to choose audience.
    Payload should pass validate_refresh_token function.
    """
    payload["aud"] = ["vortex:refresh"]
    payload["iat"] = datetime.datetime.utcnow()
    return jwt.encode(
        payload, Configuration.refresh_token_secret, algorithm="HS256"
    ).decode()


def generate_token(request, refresh_token, audience=tuple(), **validate_args):
    """
    Data in RefreshToken will be encoded in auth payload
    """
    token_payload = Configuration.decode(
        refresh_token,
        Configuration.refresh_token_secret,
        algorithm="HS256",
        audience=("vortex:refresh",),
    )

    is_valid = Configuration.validate_refresh_token(
        request, token_payload, **validate_args
    )

    if not is_valid:
        raise InvalidRefreshToken()

    audience = Configuration.audience + list(audience)
    now = datetime.datetime.utcnow()
    token_payload.update(
        {
            "aud": list(audience),
            "iat": now,
            "exp": now + datetime.timedelta(hours=Configuration.auth_token_expiry),
        }
    )

    return jwt.encode(
        token_payload, Configuration.auth_secret, algorithm="HS256"
    ).decode()

