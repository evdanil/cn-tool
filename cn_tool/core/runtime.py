"""A persistent operation runtime independent of terminal exit and presentation."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from cn_tool.core.base import BaseModule, ScriptContext
from cn_tool.core.interaction import CredentialInteraction


class SetupRequired(Exception):
    """The configured runtime cannot perform a lookup yet."""

    code = 2

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def abort_initialization(ctx: ScriptContext, *, exit_code: int = 3) -> None:
    """Release opened resources without sending/deleting an existing report."""
    from cn_tool.utils.app_lifecycle import shutdown_resources

    send_on_exit = ctx.cfg.get("email_send_on_exit")
    ctx.cfg["email_send_on_exit"] = False
    try:
        shutdown_resources(ctx, exit_code, quiet=True)
    finally:
        if send_on_exit is None:
            ctx.cfg.pop("email_send_on_exit", None)
        else:
            ctx.cfg["email_send_on_exit"] = send_on_exit


@dataclass
class RuntimeSession:
    ctx: ScriptContext
    modules: Dict[str, BaseModule]
    closed: bool = field(default=False, init=False)

    @classmethod
    def open(cls, *, config_file: Optional[Path], interaction: CredentialInteraction) -> "RuntimeSession":
        from cn_tool import main
        from cn_tool.utils.cache import CacheManager
        from cn_tool.utils.file_io import start_worker

        arguments = [] if config_file is None else ["-c", str(config_file)]
        args = main._build_parser().parse_args(arguments)
        ctx, modules = main._startup(
            args, interaction=interaction, enabled_commands=frozenset({"subnet"}), presentation=False,
        )
        try:
            # Subnet lookup uses the cache but never indexes configuration repositories.
            if ctx.cfg.get("cache_enabled", False):
                ctx.cache = CacheManager.get_instance(
                    directory=ctx.cfg["cache_directory"], logger=ctx.logger, cfg=ctx.cfg,
                )
            start_worker()
        except BaseException:
            abort_initialization(ctx)
            raise
        return cls(ctx, modules)

    def close(self, exit_code: int = 0, message: str = '') -> None:
        from cn_tool.utils.app_lifecycle import shutdown_resources

        if self.closed:
            return
        self.closed = True
        shutdown_resources(self.ctx, exit_code, message, quiet=True)
