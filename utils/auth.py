import os
from typing import Optional, Tuple
from core.base import ScriptContext
from utils.gpg import get_gpg_credentials
from utils.user_input import read_user_input
from utils.display import console, get_global_color_scheme
from utils.app_lifecycle import exit_now


def get_auth_creds(ctx: ScriptContext) -> Tuple[Optional[str], Optional[str]]:
    """
    Retrieves user credentials from environment variables, GPG file, or interactive prompt.
    The credentials are also stored in the context object.
    """
    logger = ctx.logger
    colors = get_global_color_scheme(ctx.cfg)

    username = os.getenv("USER")
    password = os.getenv("TACACS_PW")

    if not password:
        logger.info("Auth - TACACS_PW not set, checking GPG credentials")
        creds = get_gpg_credentials(ctx)
        if creds:
            username, password = creds
            logger.info("Auth - GPG credentials obtained")
        else:
            logger.info("Auth - GPG credentials not available, requesting credential from user")
            while not password:
                console.clear()
                console.print(f"\n[{colors['description']}]Set up the '[{colors['error']}]TACACS_PW[/]' environment variable to avoid typing credentials.[/]\n")
                password = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Provide security credential:[/]", True)

    if not username:
        logger.info("Auth - USER not set, requesting username")
        username = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Provide username:[/]")
        if not username:
            logger.error("Auth - username is required but not provided")
            exit_now(ctx, 1, "Username is required for authentication.")
            return (None, None)

    if username:
        ctx.username = str(username)
    if password:
        ctx.password = str(password)

    return (username, password)
