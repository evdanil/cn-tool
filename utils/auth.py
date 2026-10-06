import os
import sys
import threading
from typing import Optional, Tuple

from rich.markup import escape

from core.base import ScriptContext


_auth_lock = threading.Lock()



def credentials_hint(ctx: ScriptContext) -> str:
    """How to give cn credentials when nobody can be asked: it names the GPG file that would have been used."""
    return (
        f"set TACACS_PW or refresh the GPG credentials file {ctx.cfg.get('gpg_credentials')} "
        "(files older than 24 h are ignored)"
    )


def no_credentials_message(ctx: ScriptContext) -> str:
    """Why a run without a terminal stops."""
    return f"cn: no Infoblox credentials: {escape(credentials_hint(ctx))}"


def _can_prompt() -> bool:
    """A person can answer a prompt only when stdin is a terminal and so is the stream the console prompts on.

    That stream is stderr in command mode (``console.set_stderr(True)``) and stdout in the menu, so
    ``cn 2>cn.log`` still prompts in the menu while ``cn ip ... 2>/dev/null`` never hangs on a prompt.
    """
    from utils.display import console

    prompt_stream = sys.stderr if console.stderr else sys.stdout
    return sys.stdin.isatty() and prompt_stream.isatty()


def credential_source(ctx: ScriptContext) -> Optional[str]:
    """
    Where ``get_auth_creds`` would find the credentials, in its order, without logging in:
    ``"TACACS_PW"``, ``"GPG file <path>"``, ``"prompt"``, or None when it would end the run (3).

    It never prompts, prints or exits. The GPG file is decrypted to find out whether it works, so
    ``gpg`` may ask for its passphrase, as it does for any lookup.
    """
    from utils.gpg import get_gpg_credentials

    if os.getenv("TACACS_PW"):
        # the user name comes from $USER, or from a prompt
        return "TACACS_PW" if os.getenv("USER") or _can_prompt() else None
    if get_gpg_credentials(ctx):
        return f"GPG file {ctx.cfg.get('gpg_credentials')}"
    return "prompt" if _can_prompt() else None


def get_auth_creds(ctx: ScriptContext) -> Tuple[Optional[str], Optional[str]]:
    """
    Retrieves user credentials from environment variables, GPG file, or interactive prompt.
    The credentials are also stored in the context object.

    Without a terminal (cron, ``ssh host cn ...``) nothing is ever prompted: missing credentials
    end the run with exit status 3.
    """
    from utils.app_lifecycle import exit_now
    from utils.display import console, get_global_color_scheme
    from utils.gpg import get_gpg_credentials
    from utils.user_input import read_user_input

    logger = ctx.logger
    colors = get_global_color_scheme(ctx.cfg)

    interactive = _can_prompt()
    username = os.getenv("USER")
    password = os.getenv("TACACS_PW")

    if not password:
        logger.info("Auth - TACACS_PW not set, checking GPG credentials")
        creds = get_gpg_credentials(ctx)
        if creds:
            username, password = creds
            logger.info("Auth - GPG credentials obtained")
        elif not interactive:
            logger.error("Auth - no credentials available and no terminal to ask on")
            exit_now(ctx, 3, no_credentials_message(ctx))
            return (None, None)
        else:
            logger.info("Auth - GPG credentials not available, requesting credential from user")
            while not password:
                console.print(f"\n[{colors['description']}]Set up the '[{colors['error']}]TACACS_PW[/]' environment variable to avoid typing credentials.[/]\n")
                password = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Provide security credential:[/]", True)

    if not username:
        logger.info("Auth - USER not set, requesting username")
        username = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Provide username:[/]") if interactive else ""
        if not username:
            logger.error("Auth - username is required but not provided")
            exit_now(ctx, 3, "Username is required for authentication.")
            return (None, None)

    if username:
        ctx.username = str(username)
    if password:
        ctx.password = str(password)

    return (username, password)


def install_context_credentials(ctx: ScriptContext, username: str, password: str) -> None:
    """
    Store credentials on the shared context without touching any transport session.
    """
    ctx.username = str(username)
    ctx.password = str(password)


def ensure_device_auth(ctx: ScriptContext) -> Tuple[str, str]:
    """
    Lazily ensure shared TACACS/GPG credentials exist on the context.

    Serialised via a module-level lock so concurrent workers never race into
    duplicate interactive prompts.
    """
    from utils.app_lifecycle import exit_now

    if ctx.username and ctx.password:
        return (ctx.username, ctx.password)

    with _auth_lock:
        if ctx.username and ctx.password:
            return (ctx.username, ctx.password)

        username, password = get_auth_creds(ctx)
        if not username or not password:
            ctx.logger.error("Auth - credentials are required but incomplete")
            exit_now(ctx, 3, "Authentication error - verify credentials.")

        install_context_credentials(ctx, str(username), str(password))
        return (ctx.username, ctx.password)


def install_infoblox_auth(ctx: ScriptContext, username: str, password: str) -> None:
    """
    Stores credentials on the shared context and applies them to the shared HTTP session.
    """
    from utils.api import session

    install_context_credentials(ctx, username, password)
    session.auth = (ctx.username, ctx.password)


def ensure_infoblox_auth(ctx: ScriptContext) -> Tuple[str, str]:
    """
    Lazily ensure Infoblox credentials are available on the context and session.
    """
    username, password = ensure_device_auth(ctx)
    install_infoblox_auth(ctx, username, password)
    return (ctx.username, ctx.password)
