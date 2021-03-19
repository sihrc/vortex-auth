import jwt
import datetime

from .config import Configuration
from .errors import InvalidRefreshToken, InvalidToken, ExpiredToken


class TokenManager:
    @classmethod
    def decode_token(cls, token, audience=()):
        try:
            data = jwt.decode(
                token,
                Configuration.auth_token_secret,
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

    @classmethod
    def decode_refresh_token(cls, request, token, **validate_args):
        try:
            token_payload = jwt.decode(
                token,
                Configuration.refresh_token_secret,
                algorithm="HS256",
                audience=["vortex:refresh"],
            )
        except (jwt.DecodeError, jwt.InvalidAudienceError):
            raise InvalidToken()
        else:
            rt_id = token_payload["rt_id"]
            user_info = Configuration.validate_refresh_token(
                request, rt_id, token_payload, **validate_args
            )

            if not user_info:
                raise InvalidRefreshToken()

            return rt_id, user_info

    @classmethod
    def generate_refresh_token(cls, rt_id, payload=None):
        """
        No option to choose audience.
        Payload should pass validate_refresh_token function.
        """
        payload = payload or {}
        payload.update(
            {
                "rt_id": rt_id,
                "aud": ["vortex:refresh"],
                "iat": datetime.datetime.utcnow(),
            }
        )
        return jwt.encode(
            payload, Configuration.refresh_token_secret, algorithm="HS256"
        ).decode()

    @classmethod
    def generate_token(
        cls,
        request,
        refresh_token=None,
        audience=tuple(),
        user_info=None,
        **validate_args,
    ):
        """
        Data in RefreshToken will be encoded in auth payload
        """
        if not user_info:
            _, user_info = cls.decode_refresh_token(request, refresh_token)

        audience = Configuration.audience + tuple(audience)
        now = datetime.datetime.utcnow()

        return jwt.encode(
            {
                "aud": list(audience),
                "iat": now,
                "exp": now + datetime.timedelta(hours=Configuration.auth_token_expiry),
                **user_info,
            },
            Configuration.auth_token_secret,
            algorithm="HS256",
        ).decode()

    @classmethod
    def clear_cookies(cls, response, auth_token=None, refresh_token=None):
        response.set_cookie(
            Configuration.auth_cookie_name,
            "",
            domain=Configuration.cookie_domain,
            max_age=0,
        )

        response.set_cookie(
            Configuration.refresh_cookie_name,
            "",
            domain=Configuration.cookie_domain,
            max_age=0,
        )
        return response

    @classmethod
    def set_cookies(cls, response, auth_token=None, domain=None, refresh_token=None):
        if auth_token:
            response.set_cookie(
                Configuration.auth_cookie_name,
                auth_token,
                domain=domain or Configuration.cookie_domain,
                secure=Configuration.secure_cookies,
                max_age=(Configuration.auth_token_expiry + 1) * 60,
            )
        if refresh_token:
            response.set_cookie(
                Configuration.refresh_cookie_name,
                refresh_token,
                secure=Configuration.secure_cookies,
                domain=domain or Configuration.cookie_domain,
            )
        return response
