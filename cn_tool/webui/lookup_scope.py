"""The Infoblox scope of one web lookup: the login is checked against the grid before it is trusted.

`ensure_lookup_scope` resolves the network view for a lookup and signs in on the way. A password typed into the
sign-in dialog and refused is asked for again, at most `SIGN_IN_TRIES` times in one lookup; every other refusal ends
the lookup. No password is kept here: a refused pair is remembered as a keyed digest for the session only.
"""
from threading import Lock

from cn_tool.core.runtime import SetupRequired
from .protocol import SIGN_IN_TRIES

def _refusal_key(runtime, account):
    """Keep session-local refusal fingerprints without retaining old passwords."""
    import hashlib
    import secrets
    if not hasattr(runtime, '_webui_refusal_key'):
        runtime._webui_refusal_key = secrets.token_bytes(32)
        runtime._webui_refusals = set()
        runtime._webui_refusal_lock = Lock()
    digest = hashlib.blake2b(key=runtime._webui_refusal_key, digest_size=32)
    for value in (account.username, account.password):
        encoded = value.encode('utf-8')
        digest.update(len(encoded).to_bytes(8, 'big'))
        digest.update(encoded)
    return digest.digest()


def _remember_refusal(runtime, account):
    fingerprint = _refusal_key(runtime, account)
    with runtime._webui_refusal_lock:
        runtime._webui_refusals.add(fingerprint)


def _was_refused(runtime, account):
    fingerprint = _refusal_key(runtime, account)
    with runtime._webui_refusal_lock:
        return fingerprint in runtime._webui_refusals


def infoblox_configured(cfg):
    """Whether the settings name an Infoblox API endpoint and leave Infoblox on: the test a lookup and ``ready`` share."""
    endpoint = str(cfg.get('api_endpoint') or '').strip()
    return bool(cfg.get('infoblox_enabled')) and bool(endpoint) and endpoint != 'API_URL'


def ensure_lookup_scope(runtime, interaction, control, budget=None):
    """
    Resolve the view afresh for one lookup, checking the grid before trusting a login (`_resolve_scope`).

    A refusal of a password that the sign-in dialog was answered with during this call (``interaction.typed_count``
    moved) is not the end: the login is already dropped, so the next pass asks again, and the dialog is told that
    the last password was refused and how many tries are left (``interaction.sign_in_refused``; the first dialog
    is told all of them, ``interaction.sign_in_begins``, which is how the page knows that the answer is checked
    here and that `credentials_checked` or the next request will follow). The third refusal
    is raised, as is every refusal of a login that was not typed here (a saved one, one typed in an earlier lookup,
    one from the settings), and every other error. ``interaction.sign_in_settled(checked)`` ends it either way;
    ``checked``: a typed password was used and not refused. An interaction without ``typed_count`` never asks twice.
    """
    def typed():
        return getattr(interaction, 'typed_count', None)
    first = seen = typed()
    if first is not None:
        interaction.sign_in_begins(SIGN_IN_TRIES)  # a password asked for from here on is one of this lookup's tries
    refusals = 0
    accepted = False
    try:
        while True:
            try:
                scope = _resolve_scope(runtime, interaction, control, budget)
                accepted = True
                return scope
            except SetupRequired as refusal:
                now = typed()
                typed_here, seen = now != seen, now
                if not getattr(refusal, 'sign_in_again', False) or not typed_here:
                    raise
                refusals += 1
                if refusals >= SIGN_IN_TRIES:
                    raise
                control.checkpoint()
                interaction.sign_in_refused(SIGN_IN_TRIES - refusals)
    finally:
        if first is not None:
            interaction.sign_in_settled(accepted and typed() != first)


def _resolve_scope(runtime, interaction, control, budget=None):
    """One pass of `ensure_lookup_scope`: the login from the settings, the session or the dialog, and one request."""
    from cn_tool.modules.subnet_request import request_result
    from cn_tool.core.base import Credentials
    from cn_tool.utils import api, auth
    from cn_tool.utils.network_views import view_scope
    from .texts import refused_password
    import os

    ctx = runtime.ctx
    cfg = ctx.cfg
    if not infoblox_configured(cfg):
        from cn_tool.utils.config import user_config_path
        paths = cfg.get('config_files') or []
        path = paths[-1] if paths else user_config_path()
        raise SetupRequired(f'Infoblox is not set up. Open Settings and enter the API endpoint ([api] endpoint in {path}).')
    control.checkpoint()
    previous = (ctx.username, ctx.password, ctx.infoblox_credentials, api.session.auth,
                getattr(ctx, '_webui_infoblox_account', None))
    refused_attempt = False
    try:
        account = ctx.infoblox_credentials
        own = auth.infoblox_account_configured(ctx)
        own_username = (auth._env_user(ctx) or auth._api_user(ctx)) if own else ''
        previous_own_username = getattr(runtime, '_webui_own_username', own_username)
        if account is not None and (not own or own_username != previous_own_username):
            ctx.infoblox_credentials = account = None
        needs_device_login = not own and not ctx.password
        prompt_count = getattr(interaction, 'prompt_count', 0)
        if not own:
            source = getattr(runtime, '_webui_device_source', None)
            if ctx.password and source == auth._name(ctx, 'auth_device_password_var'):
                if os.getenv(source) != ctx.password or (os.getenv(auth._name(ctx, 'auth_device_user_var')) or ctx.username) != ctx.username:
                    ctx.username = ctx.password = ''
            if not ctx.password:
                password_name = auth._name(ctx, 'auth_device_password_var')
                runtime._webui_device_source = password_name if os.getenv(password_name) else None
                needs_device_login = True
        if account is not None and account.source not in ('', 'prompt'):
            found = auth._infoblox_settings(ctx)
            if (found.conflict or found.password != account.password or found.password_from != account.source
                    or (found.username and found.username != account.username)):
                ctx.infoblox_credentials = None
        username, _ = auth.ensure_infoblox_auth(ctx)
        if (needs_device_login and runtime._webui_device_source is None
                and getattr(interaction, 'prompt_count', 0) != prompt_count):
            runtime._webui_device_source = 'prompt'
        control.checkpoint()
        refused = getattr(runtime, '_webui_refused', None)
        account = ctx.infoblox_credentials
        if not own:
            current = getattr(ctx, '_webui_infoblox_account', None)
            if current is None or (current.username, current.password) != (ctx.username, ctx.password):
                current = Credentials(ctx.username, ctx.password)
            ctx._webui_infoblox_account = current
            account = current
        if refused is not None and account is not None and (account.username, account.password) == (refused.username, refused.password):
            if own:
                ctx.infoblox_credentials = refused
            else:
                ctx._webui_infoblox_account = refused
        def typed():
            # The login was typed into the sign-in dialog (or came from the credential store through it), not read
            # from the settings or the environment: once refused it is dropped, and the next lookup asks again.
            if own:
                return account is not None and account.source == 'prompt'
            return getattr(runtime, '_webui_device_source', None) == 'prompt'
        if account is not None and _was_refused(runtime, account):
            runtime._webui_refused = account
            refused_attempt = True
            if typed():
                raise refused_password(SetupRequired, account.username)
            raise SetupRequired('Infoblox previously refused this login. Enter different credentials.')
        responses = []
        def discover(*args, **kwargs):
            if budget is not None:
                result = request_result(*args, **kwargs, paged=True, budget=budget)
            else:
                result = request_result(*args, **kwargs)
            responses.append(result)
            return result
        scope = view_scope(ctx, None, discover)
        scope.grid()
        result = responses[-1]
        if result.status_code == 401 and account is not None:
            refused_attempt = True
            _remember_refusal(runtime, account)
            runtime._webui_refused = refused if refused is not None and (account.username, account.password) == (refused.username, refused.password) else account
            retype = typed()
            if own and account.source == 'prompt':
                ctx.infoblox_credentials = None
            elif not own and getattr(runtime, '_webui_device_source', None) == 'prompt':
                ctx.username = ctx.password = ''
            control.checkpoint()
            if retype:
                raise refused_password(SetupRequired, account.username)
        control.checkpoint()
        if budget is not None:
            if result.status == 'redirect_error':
                raise SetupRequired('Infoblox redirected the preview request; check the configured API endpoint.')
            if result.truncated:
                raise SetupRequired('Network view lookup is incomplete; narrow the lookup.')
            fallback_403 = result.status_code == 403 and not scope.requested
            if not fallback_403 and (not result.ok or scope.grid().error):
                raise SetupRequired('Network view lookup failed; check the Infoblox API endpoint and access.')
        if not result.ok and (result.status_code != 403 or scope.requested):
            if result.status == 'not_found':
                raise SetupRequired(f'Network view discovery failed (HTTP {result.status_code}). Check the Infoblox API endpoint.')
            raise SetupRequired(result.message)
        problem = scope.problem()
        if problem:
            raise SetupRequired(problem.message)
        interaction.select('infoblox' if auth.infoblox_account_configured(ctx) else 'device', username)
        scope._webui_verified = result.ok
        scope._webui_username = username
        scope._webui_fallback = bool(scope.grid().error)
        scope._webui_previous = previous
        scope._webui_previous_own_username = previous_own_username
        runtime._webui_own_username = own_username
        return scope
    except BaseException:
        ctx.username, ctx.password, ctx.infoblox_credentials, api.session.auth, ctx._webui_infoblox_account = previous
        refused = getattr(runtime, '_webui_refused', None)
        if refused_attempt and refused is not None:
            restored = ctx.infoblox_credentials
            if restored is refused and restored.source == 'prompt':
                ctx.infoblox_credentials = None
                api.session.auth = None
            elif (restored is None and getattr(runtime, '_webui_device_source', None) == 'prompt'
                  and (ctx.username, ctx.password) == (refused.username, refused.password)):
                ctx.username = ctx.password = ''
                ctx._webui_infoblox_account = None
                api.session.auth = None
        raise
