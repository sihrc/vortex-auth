import logging
from vortex.errors import VortexException


class Configuration(object):
    configured = False

    logger = logging.getLogger("vortex.auth")
    exc_cls = VortexException
    audience = ["vortex:base"]
    auth_cookie_name = "auth_token"
    cookie_domain = NotImplemented
    auth_secret = NotImplemented


def configure(
    token_secret,
    refresh_token_secret,
    cookie_domain,
    audience=(),
    auth_cookie_name="auth_token",
    refresh_cookie_name="refresh_token",
    exc_cls=None,
):
    if Configuration.configured:
        raise RuntimeError("configure cannot be called twice")

    assert isinstance(audience, (list, tuple, set)), "audience must be list,tuple,set"

    Configuration.audience = audience
    Configuration.auth_cookie_name = auth_cookie_name
    Configuration.auth_token_expiry = 120
    Configuration.configured = True
    Configuration.refresh_cookie_name = refresh_cookie_name
    Configuration.refresh_token_secret = refresh_token_secret
    Configuration.token_secret = token_secret
    # Offload to another service or uses default
    Configuration.generate_token = None
    Configuration.validate_refresh_token = lambda request, token_payload: False


def check_config():
    if not Configuration.configured:
        raise RuntimeError(
            "vortex.auth.config.configured was not run. Must be run once."
        )
