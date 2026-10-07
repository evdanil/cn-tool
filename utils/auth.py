import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple, Optional, Tuple

from rich.markup import escape

from core.base import Credentials, ScriptContext


_auth_lock = threading.Lock()


# The names of the environment variables cn reads for credentials come from [auth] in .cn (utils.config:
# the defaults USER, TACACS_PW, INFOBLOX_USER and INFOBLOX_PW live there and nowhere else). Every read goes
# through _name, every name a text prints through _shown (a custom name is printed only when that variable
# exists, else the key that holds it), so a password typed into an [auth] key by mistake is never echoed.


def _cfg(ctx: ScriptContext) -> Any:
    return getattr(ctx, "cfg", None) or {}


def _name(ctx: ScriptContext, key: str) -> str:
    """The variable the cfg key names (its default when blank). Valid once ``_problem`` is ""."""
    from utils.config import env_name

    return env_name(_cfg(ctx), key)


def _shown(ctx: ScriptContext, key: str) -> str:
    """How a text names that variable: its name when it is the default or exists, else "the variable named in [auth] <key>"."""
    from utils.config import shown_env_name

    return shown_env_name(_cfg(ctx), key)


def _problem(ctx: ScriptContext) -> str:
    """"" when the four [auth] names are usable, else why not (names the key, never the value)."""
    from utils.config import env_name_problem

    return env_name_problem(_cfg(ctx))


def _end_run_for_bad_names(ctx: ScriptContext, problem: str) -> None:
    """A wrong [auth] setting ends the login with exit status 2: the fix is an edit of .cn."""
    from utils.app_lifecycle import exit_now

    ctx.logger.error("Auth - %s", problem)
    exit_now(ctx, 2, f"cn: {escape(problem)}")


def _is_name(ctx: ScriptContext, key: str, shown: str) -> bool:
    """Whether ``shown`` (from ``_shown``) is the variable's name rather than the key that holds it."""
    return shown == _name(ctx, key)


def credentials_hint(ctx: ScriptContext) -> str:
    """How to give cn credentials when nobody can be asked: it names the GPG file that would have been used."""
    return (
        f"set {_shown(ctx, 'auth_device_password_var')} or refresh the GPG credentials file "
        f"{ctx.cfg.get('gpg_credentials')} (files older than 24 h are ignored)"
    )


def no_credentials_message(ctx: ScriptContext) -> str:
    """Why a run without a terminal stops: the TACACS login is missing.

    Says "Infoblox" while Infoblox uses the TACACS login (it is Infoblox that needs it), and "TACACS" when
    Infoblox has its own account and something else (devices, Active Directory) needs the TACACS login.
    """
    who = "TACACS" if infoblox_account_configured(ctx) else "Infoblox"
    return f"cn: no {who} credentials: {escape(credentials_hint(ctx))}"


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
    Where ``get_auth_creds`` would find the TACACS login, in its order, without logging in:
    the name of the password variable (by default ``"TACACS_PW"``), ``"GPG file <path>"``, ``"prompt"``, or
    None when it would end the run (3). Infoblox's own account is ``infoblox_source``.

    It never prompts, prints or exits. The GPG file is decrypted to find out whether it works, so
    ``gpg`` may ask for its passphrase, as it does for any lookup. With a wrong [auth] setting it returns
    None without reading anything (``cn doctor`` reports the setting first).
    """
    from utils.gpg import get_gpg_credentials

    if _problem(ctx):
        return None
    password_var = _name(ctx, "auth_device_password_var")
    if os.getenv(password_var):
        # the user name comes from the user variable, or from a prompt
        return password_var if os.getenv(_name(ctx, "auth_device_user_var")) or _can_prompt() else None
    if get_gpg_credentials(ctx):
        return f"GPG file {ctx.cfg.get('gpg_credentials')}"
    return "prompt" if _can_prompt() else None


def get_auth_creds(ctx: ScriptContext) -> Tuple[Optional[str], Optional[str]]:
    """
    Retrieves the TACACS login from environment variables, GPG file, or interactive prompt.
    The credentials are also stored in the context object.

    The variables are the ones ``[auth] device_user_var`` and ``device_password_var`` name (by default
    ``USER`` and ``TACACS_PW``). Without a terminal (cron, ``ssh host cn ...``) nothing is ever prompted:
    missing credentials end the run with exit status 3, and a wrong [auth] setting with exit status 2.
    """
    from utils.app_lifecycle import exit_now
    from utils.display import console, get_global_color_scheme
    from utils.gpg import get_gpg_credentials
    from utils.user_input import read_user_input

    problem = _problem(ctx)
    if problem:
        _end_run_for_bad_names(ctx, problem)
        return (None, None)

    logger = ctx.logger
    colors = get_global_color_scheme(ctx.cfg)

    interactive = _can_prompt()
    username = os.getenv(_name(ctx, "auth_device_user_var"))
    password = os.getenv(_name(ctx, "auth_device_password_var"))

    if not password:
        logger.info("Auth - %s not set, checking GPG credentials", _shown(ctx, "auth_device_password_var"))
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
                console.print(_tacacs_password_hint(ctx, colors))
                password = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Provide security credential:[/]", True)

    if not username:
        logger.info("Auth - %s not set, requesting username", _shown(ctx, "auth_device_user_var"))
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


def _tacacs_password_hint(ctx: ScriptContext, colors: Any) -> str:
    """The line printed before the TACACS password prompt, as Rich markup (a blank line each side).

    A name that exists (or is the default) reads ``Set up the 'TACACS_PW' environment variable ...``; the
    key that holds a name that does not exist reads ``Set up the variable named in [auth] device_password_var
    ...``. The shown text is escaped before it is wrapped in colour tags: Rich reads ``[auth]`` as a style.
    """
    shown = _shown(ctx, "auth_device_password_var")
    if _is_name(ctx, "auth_device_password_var", shown):
        subject = f"the '[{colors['error']}]{escape(shown)}[/]' environment variable"
    else:
        subject = f"[{colors['error']}]{escape(shown)}[/]"
    return f"\n[{colors['description']}]Set up {subject} to avoid typing credentials.[/]\n"


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


# ---------------------------------------------------------------------------
# Infoblox's own account
#
# Infoblox logs in with the TACACS login (above) unless one of INFOBLOX_USER, INFOBLOX_PW, [api] user or
# [gpg] infoblox_credentials is set. Once any of them is set, Infoblox never uses the TACACS login: a missing
# half is asked for on a terminal, and without one the run ends with exit status 3 and says which half.
# ---------------------------------------------------------------------------

class InfobloxSource(NamedTuple):
    """Where an Infoblox login would find its account, found without prompting, printing or exiting.

    This is what ``cn doctor`` shows. The password itself is never part of it.
    """
    username: str         # "" when it would be asked for, or is missing
    user_from: str        # "INFOBLOX_USER", "[api] user", "GPG file <path>", "prompt", or "" when missing
    password_from: str    # "INFOBLOX_PW", "GPG file <path>", "prompt", or "" when missing
    # what a person asked for a half should know, joined with "; ": "the variable named in [auth] <key> is not
    # set" (utils.config.unset_env_note: a custom name whose variable is unset or blank) and "the Infoblox GPG
    # file <path> <reason>" (a configured file that could not be used); cn doctor shows it as a warning
    note: str = ""
    conflict: str = ""    # the file's User line when it differs from the configured name

    @property
    def complete(self) -> bool:
        """Whether a login finds both halves (or can ask for them) and the file agrees with the name."""
        return bool(self.user_from and self.password_from) and not self.conflict


@dataclass(frozen=True)
class _Found:
    """What the settings give, before any prompt. The password stays out of ``repr``."""
    username: str
    user_from: str
    password: str = field(default="", repr=False)
    password_from: str = ""
    gpg_problem: str = ""   # the GpgRead.problem of a configured file that was read and failed
    conflict: str = ""      # the file's User line, when it differs from the configured name


def _env_user(ctx: ScriptContext) -> str:
    """The Infoblox user variable's value, stripped; "" when it is unset or blank."""
    return (os.getenv(_name(ctx, "auth_infoblox_user_var")) or "").strip()


def _env_password(ctx: ScriptContext) -> str:
    """The Infoblox password variable, exactly as given; "" when it is unset or blank."""
    value = os.getenv(_name(ctx, "auth_infoblox_password_var")) or ""
    return value if value.strip() else ""


def _api_user(ctx: ScriptContext) -> str:
    value = _cfg(ctx).get("api_user")
    return value.strip() if isinstance(value, str) else ""


def _infoblox_gpg_path(ctx: ScriptContext) -> Optional[Path]:
    """``[gpg] infoblox_credentials`` expanded, or None when it is not set."""
    value = _cfg(ctx).get("gpg_infoblox_credentials")
    if isinstance(value, Path):
        return value.expanduser()
    if isinstance(value, str) and value.strip():
        return Path(value.strip()).expanduser()
    return None


def infoblox_account_configured(ctx: ScriptContext) -> bool:
    """Whether any Infoblox setting is non-empty after ``strip()``.

    The settings are the variables ``[auth] infoblox_user_var`` and ``infoblox_password_var`` name (by default
    INFOBLOX_USER and INFOBLOX_PW), ``[api] user`` and ``[gpg] infoblox_credentials``. When one is, Infoblox
    never uses the shared (TACACS) login. Call only once ``_problem(ctx)`` is "".
    """
    return bool(_env_user(ctx) or _env_password(ctx) or _api_user(ctx) or _infoblox_gpg_path(ctx) is not None)


def _infoblox_settings(ctx: ScriptContext) -> _Found:
    """Read the settings in their order, without prompting, printing or exiting.

    The user name: the user variable (INFOBLOX_USER), then ``[api] user``, then the GPG file's ``User =`` line
    (only with the file's password). The password: the password variable (INFOBLOX_PW), then the GPG file;
    the file is not decrypted while the variable is set, so gpg never asks for a passphrase it does not need.
    A file for another user than the one named is a conflict: its password belongs to another account.
    """
    env_user = _env_user(ctx)
    api_user = _api_user(ctx)
    if env_user:
        username, user_from = env_user, _name(ctx, "auth_infoblox_user_var")
    elif api_user:
        username, user_from = api_user, "[api] user"
    else:
        username, user_from = "", ""

    password = _env_password(ctx)
    if password:
        return _Found(username, user_from, password, _name(ctx, "auth_infoblox_password_var"))
    path = _infoblox_gpg_path(ctx)
    if path is None:
        return _Found(username, user_from)

    from utils.gpg import read_gpg_file

    read = read_gpg_file(ctx.logger, path, check_age=False)  # a service account's password changes rarely
    if read.problem:
        return _Found(username, user_from, gpg_problem=read.problem)
    if username and read.user != username:
        return _Found(username, user_from, conflict=read.user)
    label = f"GPG file {path}"
    return _Found(username or read.user, user_from or label, read.password, label)


def _gpg_note(ctx: ScriptContext, found: _Found) -> str:
    """"the Infoblox GPG file <path> <reason>" when a configured file was read and failed, else ""."""
    return f"the Infoblox GPG file {_infoblox_gpg_path(ctx)} {found.gpg_problem}" if found.gpg_problem else ""


def _source_of(ctx: ScriptContext, found: _Found) -> InfobloxSource:
    """The settings as ``InfobloxSource``: a missing half reads "prompt" when a person could answer.

    The note collects what a person asked for a half should know: a configured name whose variable is unset or
    blank (``the variable named in [auth] <key> is not set``; the defaults say nothing), and a GPG file that
    could not be used.
    """
    from utils.config import unset_env_note

    if found.conflict:
        return InfobloxSource(found.username, found.user_from, "", conflict=found.conflict)
    ask = "prompt" if _can_prompt() else ""
    halves = (("auth_infoblox_user_var", found.user_from), ("auth_infoblox_password_var", found.password_from))
    notes = []
    for key, given in halves:
        # a half that would be asked for says so when its custom variable is not set (empty for the defaults)
        note = unset_env_note(_cfg(ctx), key) if ask and not given else ""
        if note:
            notes.append(note)
    if found.gpg_problem:
        notes.append(_gpg_note(ctx, found))
    return InfobloxSource(found.username, found.user_from or ask, found.password_from or ask, "; ".join(notes))


def infoblox_source(ctx: ScriptContext) -> Optional[InfobloxSource]:
    """Where an Infoblox login would find its account; None when Infoblox uses the shared login.

    It never prompts, prints or exits. The Infoblox GPG file is decrypted when it is configured and
    INFOBLOX_PW is not set, so gpg may ask for its passphrase. A missing half reads "prompt" when a person
    could answer (``_can_prompt``), else "".
    """
    if not infoblox_account_configured(ctx):
        return None
    return _source_of(ctx, _infoblox_settings(ctx))


def infoblox_credentials_hint(ctx: ScriptContext, source: InfobloxSource) -> str:
    """Why an incomplete ``source`` cannot log in, and which settings fix it (plain text, for doctor too)."""
    if source.conflict:
        fix = "remove [api] user" if source.user_from == "[api] user" else f"unset {source.user_from}"
        return (
            f"conflicting Infoblox user: {source.user_from} is {source.username}, but the Infoblox GPG file "
            f"{_infoblox_gpg_path(ctx)} is for {source.conflict}; fix the file, or {fix} to use the file's user"
        )
    user_var = _shown(ctx, "auth_infoblox_user_var")
    password_var = _shown(ctx, "auth_infoblox_password_var")
    if source.username:
        if source.note:
            return f"no Infoblox password for {source.username}: {source.note}; fix it, or set {password_var}"
        return f"no Infoblox password for {source.username}: set {password_var}, or [gpg] infoblox_credentials"
    if source.password_from:
        tail = ""
        if source.password_from == _name(ctx, "auth_infoblox_password_var") and _infoblox_gpg_path(ctx) is not None:
            tail = f" (the Infoblox GPG file is not read while {password_var} is set)"
        return f"no Infoblox user: set {user_var} or [api] user{tail}"
    return f"no Infoblox credentials: {source.note}; fix it, or set {_both_variables(ctx, user_var, password_var)}"


def _both_variables(ctx: ScriptContext, user_var: str, password_var: str) -> str:
    """The two Infoblox variables as one phrase: two key forms read "the variables named in [auth] a and b"."""
    user_is_key = not _is_name(ctx, "auth_infoblox_user_var", user_var)
    password_is_key = not _is_name(ctx, "auth_infoblox_password_var", password_var)
    if user_is_key and password_is_key:
        return "the variables named in [auth] infoblox_user_var and infoblox_password_var"
    return f"{user_var} and {password_var}"


def no_infoblox_credentials_message(ctx: ScriptContext, source: InfobloxSource) -> str:
    """What the run prints when it ends because an Infoblox half is missing: "cn: " and the escaped hint."""
    return f"cn: {escape(infoblox_credentials_hint(ctx, source))}"


def _password_hint(ctx: ScriptContext, found: _Found) -> str:
    """The line printed before an Infoblox password prompt, as Rich markup (a blank line each side)."""
    from utils.display import get_global_color_scheme

    colors = get_global_color_scheme(ctx.cfg)
    before = ""
    if found.gpg_problem:
        before = f"The Infoblox GPG file {escape(str(_infoblox_gpg_path(ctx)))} {found.gpg_problem}. "
    shown = _shown(ctx, "auth_infoblox_password_var")
    if _is_name(ctx, "auth_infoblox_password_var", shown):
        subject = f"'[{colors['error']}]{escape(shown)}[/]'"
    else:  # the key form holds [auth]: escaped before it is wrapped in colour tags
        subject = f"[{colors['error']}]{escape(shown)}[/]"
    return f"\n[{colors['description']}]{before}Set {subject} to avoid typing the Infoblox password.[/]\n"


def get_infoblox_creds(ctx: ScriptContext) -> Optional[Credentials]:
    """Resolve Infoblox's own account: the settings, then prompts, or the run ends with exit status 3.

    A GPG file for another user than the configured one ends the run before anything else. A missing half
    is asked for on a terminal (the user name first, so the password prompt can name the account); without
    a terminal it ends the run. Returns None only when the exit hook returns (tests). The log names the
    user and where each half came from, never the password.
    """
    from utils.app_lifecycle import exit_now
    from utils.display import console, get_global_color_scheme
    from utils.user_input import read_user_input

    logger = ctx.logger
    colors = get_global_color_scheme(ctx.cfg)
    found = _infoblox_settings(ctx)
    source = _source_of(ctx, found)

    if found.conflict:
        logger.error(
            "Auth - the Infoblox GPG file is for %s, not %s (%s)", found.conflict, found.username, found.user_from
        )
        exit_now(ctx, 3, no_infoblox_credentials_message(ctx, source))
        return None
    if found.gpg_problem:
        logger.warning("Auth - %s", _gpg_note(ctx, found))
    if not source.complete:
        logger.error("Auth - Infoblox credentials incomplete and no terminal to ask on")
        exit_now(ctx, 3, no_infoblox_credentials_message(ctx, source))
        return None

    username, user_from = found.username, source.user_from
    if not username:
        username = read_user_input(ctx, f"[{colors['header']} {colors['bold']}]Infoblox user:[/]").strip()
        if not username:
            logger.error("Auth - the Infoblox user is required but not provided")
            exit_now(ctx, 3, no_infoblox_credentials_message(ctx, InfobloxSource("", "", source.password_from)))
            return None

    password, password_from = found.password, source.password_from
    if not password:
        logger.info("Auth - asking for the Infoblox password of %s", username)
        while not password:
            console.print(_password_hint(ctx, found))
            password = read_user_input(
                ctx, f"[{colors['header']} {colors['bold']}]Infoblox password for {escape(username)}:[/]", True
            )

    logger.info("Auth - Infoblox account %s: user from %s, password from %s", username, user_from, password_from)
    return Credentials(username, password, password_from)


def infoblox_credentials_known(ctx: ScriptContext) -> bool:
    """Whether an Infoblox login needs no question now.

    True when Infoblox's own account is resolved, or when Infoblox uses the shared login and it is known
    (what the Setup menu's connection test waits for).
    """
    if _own_account(ctx) is not None:
        return True
    if infoblox_account_configured(ctx):
        return False
    return bool(getattr(ctx, "password", None))


def _own_account(ctx: ScriptContext) -> Optional[Credentials]:
    """Infoblox's own account once resolved. A test double that is not a ``Credentials`` counts as none."""
    account = getattr(ctx, "infoblox_credentials", None)
    return account if isinstance(account, Credentials) else None


def ensure_infoblox_auth(ctx: ScriptContext) -> Tuple[str, str]:
    """
    Lazily ensure Infoblox credentials are available on the context and session.

    1. Infoblox's own account, once resolved (``ctx.infoblox_credentials``), is used as it is.
    2. A wrong [auth] setting ends the run with exit status 2 (checked here whichever login follows). With no
       Infoblox setting present, Infoblox uses the shared (TACACS) login exactly as it always did:
       ``ensure_device_auth``, then ``install_infoblox_auth``.
    3. Otherwise the account is resolved once, under the same lock as the TACACS login so two prompts never
       interleave (``get_infoblox_creds``: the settings, then prompts, or exit status 3), and stored on the
       context.

    The session's authentication is written on every call with the account's pair. Infoblox's own account
    never touches ``ctx.username`` / ``ctx.password``, so a device query or an AD bind still gets the TACACS
    login. If the exit hook returns (tests only) the result is ``("", "")`` and the session is not touched.
    """
    account = _own_account(ctx)
    if account is None:
        problem = _problem(ctx)
        if problem:  # every login checks all four [auth] names, whichever it uses
            _end_run_for_bad_names(ctx, problem)
            return ("", "")
        if not infoblox_account_configured(ctx):
            username, password = ensure_device_auth(ctx)
            install_infoblox_auth(ctx, username, password)
            return (ctx.username, ctx.password)
        with _auth_lock:
            account = _own_account(ctx)
            if account is None:
                account = get_infoblox_creds(ctx)
                if account is None:
                    return ("", "")
                ctx.infoblox_credentials = account

    from utils.api import session

    session.auth = (account.username, account.password)
    return (account.username, account.password)