from typing import Optional

from core.base import BaseModule, ScriptContext
from utils.email_helper import interpret_bool, send_configured_report
from utils.user_input import press_any_key


class EmailReportModule(BaseModule):
    """Module to manually trigger sending the report file via email."""

    @property
    def visibility_config_key(self) -> Optional[str]:
        return "email_enabled"

    @property
    def menu_key(self) -> str:
        return "e"

    @property
    def menu_title(self) -> str:
        return "Send Report via Email"

    def run(self, ctx: ScriptContext) -> None:
        if not interpret_bool(ctx.cfg.get("email_enabled")):
            ctx.console.print("[red]Email feature is disabled in configuration.[/red]")
            press_any_key(ctx)
            return

        ctx.logger.info("Request Type - Manual Email Report")
        ctx.console.print("[cyan]Attempting to send the report via email...[/]")

        receiver = ctx.cfg.get("email_to")
        success = send_configured_report(
            ctx,
            report_path=ctx.cfg.get("report_file"),
            receiver=receiver,
            prefix="EMAIL (manual)",
            success_message=f"[green]Report has been sent successfully to {receiver}.[/green]" if receiver else None,
            failure_message="[red]Failed to send the report. Please check the logs for details.[/red]",
        )

        if success is False:
            ctx.logger.debug("EMAIL (manual): send_configured_report returned False")

        press_any_key(ctx)
