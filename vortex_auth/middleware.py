from aiohttp.web import middleware

from vortex.logger import Logging

from .config import Configuration
from .errors import LoginRequired
from .token import decode_token, generate_token
from .user import AuthUser

logger = Logging.get("request.auth")


@middleware
async def auth_middleware(request, handler):
    if not request.middleware_configs.get("login_required"):
        return await handler(request)

    auth_token = request.cookies.get(Configuration.auth_cookie_name)
    assign_cookie = False

    # Check Headers
    if not auth_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            auth_token = auth_header.split()[-1]

    if not auth_token:
        refresh_token = request.cookies.get(Configuration.refresh_cookie_name)
        if not refresh_token:
            # Login or acquire auth/refresh token
            raise LoginRequired()
        generate_token_fn = Configuration.generate_token or generate_token
        auth_token = await generate_token_fn(refresh_token)
        assign_cookie = True

    request.current_user = AuthUser(decode_token(auth_token))
    logger.debug(f"Authenticated User {request.current_user}")

    response = await handler(request)

    if assign_cookie:
        response.set_cookie(
            Configuration.auth_cookie_name,
            auth_token,
            domain=Configuration.cookie_domain,
            secure=True,
            max_age=(Configuration.auth_token_expiry + 1) * 60,
        )
    return response