from aiohttp.web import middleware

from .config import Configuration
from .errors import LoginRequired
from .token import TokenManager
from .holder import Auth


@middleware
async def auth_middleware(request, handler):
    request.auth = Auth()
    if not request.middleware.configs.get("login_required"):
        return await handler(request)

    request.auth.token = auth_token = request.cookies.get(
        Configuration.auth_cookie_name
    )
    request.auth.refresh_token = refresh_token = request.cookies.get(
        Configuration.refresh_cookie_name
    )

    assign_cookie = False
    # Check Headers
    if not auth_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            auth_token = auth_header.split()[-1]

    if not auth_token:
        if not refresh_token:
            # Login or acquire auth/refresh token
            raise LoginRequired()
        generate_token_fn = Configuration.generate_token or TokenManager.generate_token
        auth_token = await generate_token_fn(request, refresh_token)
        assign_cookie = True

    info = TokenManager.decode_token(auth_token)
    info["rt"] = refresh_token
    request.auth.values.update(info)

    response = await handler(request)

    if assign_cookie:
        response.set_cookie(
            Configuration.auth_cookie_name,
            auth_token,
            domain=Configuration.cookie_domain,
            secure=Configuration.secure_cookies,
            max_age=(Configuration.auth_token_expiry + 1) * 60,
        )
    return response
