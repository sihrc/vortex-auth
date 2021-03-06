import logging
from vortex.errors import VortexException


class Configuration(object):
    configured = False

    logger = logging.getLogger("vortex.auth")
    exc_cls = VortexException
    audience = ["vortex:base"]
    auth_cookie_name = "auth_token"
    cookie_domain = None
    auth_token_secret = None
    secure_cookies = True
    validate_refresh_token = None


def configure(
    auth_token_secret,
    refresh_token_secret,
    cookie_domain,
    audience=("vortex:base",),
    auth_cookie_name="auth_token",
    refresh_cookie_name="refresh_token",
    forgot_password_secret=None,
    forgot_password_expiry=15 * 60,  # 15 minutes
    generate_token=None,
    secure_cookies=True,
    validate_refresh_token=lambda request, token_payload: False,
):
    if Configuration.configured:
        raise RuntimeError("configure cannot be called twice")

    assert isinstance(audience, (list, tuple, set)), "audience must be list,tuple,set"

    Configuration.cookie_domain = cookie_domain
    Configuration.audience = audience
    Configuration.auth_cookie_name = auth_cookie_name
    Configuration.auth_token_expiry = 120
    Configuration.secure_cookies = secure_cookies
    Configuration.configured = True
    Configuration.refresh_cookie_name = refresh_cookie_name
    Configuration.refresh_token_secret = refresh_token_secret
    Configuration.forgot_password_secret = forgot_password_secret
    Configuration.forgot_password_expiry = forgot_password_expiry
    Configuration.auth_token_secret = auth_token_secret
    # Offload to another service or uses default
    Configuration.generate_token = generate_token
    Configuration.validate_refresh_token = validate_refresh_token


def check_config():
    if not Configuration.configured:
        raise RuntimeError("Authorization Plugin was not configured. Must be run once.")
