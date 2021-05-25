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
        return jwt.encode(
            {
                **payload,
                **{
                    "rt_id": rt_id,
                    "aud": ["vortex:refresh"],
                    "iat": datetime.datetime.utcnow(),
                },
            },
            Configuration.refresh_token_secret,
            algorithm="HS256",
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
        cookie_kwargs = {"max_age": 0}

        if Configuration.cookie_domain:
            cookie_kwargs["domain"] = Configuration.cookie_domain

        response.set_cookie(Configuration.auth_cookie_name, "", **cookie_kwargs)

        response.set_cookie(
            Configuration.refresh_cookie_name,
            "",
            **cookie_kwargs,
        )
        return response

    @classmethod
    def set_cookies(cls, response, auth_token=None, domain=None, refresh_token=None):
        cookie_kwargs = {
            "secure": Configuration.secure_cookies,
            "max_age": (Configuration.auth_token_expiry + 1) * 60,
        }

        domain = domain or Configuration.cookie_domain
        if domain:
            cookie_kwargs["domain"] = domain

        if auth_token:
            response.set_cookie(
                Configuration.auth_cookie_name,
                auth_token,
                domain=domain,
            )
        if refresh_token:
            response.set_cookie(
                Configuration.refresh_cookie_name,
                refresh_token,
                # secure=Configuration.secure_cookies,
                domain=domain,
            )
        return response
