from typing import Optional
from core.base import BaseModule, ScriptContext
from utils.email_helper import send_report_email


class EmailReportModule(BaseModule):
    """
    A module to manually trigger sending the report file via email.
    """

    @property
    def visibility_config_key(self) -> Optional[str]:
        # This module is only visible if the email feature is enabled.
        return "email_enabled"

    @property
    def menu_key(self) -> str:
        """The character key to trigger this module from the menu."""
        return "e"  # 'e' for email

    @property
    def menu_title(self) -> str:
        """The title of the module to display in the menu."""
        return "Send Report via Email"

    def run(self, ctx: ScriptContext) -> None:
        """
        The main entry point for the module. It gathers config, checks for the
        report file, and calls the email helper function.
        """
        # The first thing we do is check if we should even be running.
        if not ctx.cfg.get("email_enabled"):
            ctx.console.print("[red]Email feature is disabled in configuration.[/red]")
            return

        ctx.logger.info("Request Type - Manual Email Report")
        ctx.console.print("[cyan]Attempting to send the report via email...[/]")

        # --- Pre-flight Checks for good user experience ---

        # 1. Check if the report file actually exists.
        report_path = ctx.cfg.get("report_file")
        if not report_path or not report_path.is_file():
            ctx.console.print(f"[red]Error: Report file not found at '{report_path}'. Please generate a report first.[/red]")
            ctx.logger.warning("Manual email failed: Report file does not exist.")
            return  # Exit the action

        # 2. Check if a recipient is configured.
        receiver = ctx.cfg.get("email_to")
        if not receiver:
            ctx.console.print("[red]Error: Email recipient is not configured. Please set 'to' in the [email] section of your config.[/red]")
            ctx.logger.warning("Manual email failed: Recipient not configured.")
            return  # Exit the action

        # --- Call the Reusable Helper Function ---
        # This is the exact same logic used by the plugin's exit hook.
        with ctx.console.status("[green]Sending report...[/green]"):
            success = send_report_email(
                logger=ctx.logger,
                smtp_server=ctx.cfg.get("email_server", ""),
                smtp_port=int(ctx.cfg.get("email_port", 25)),
                sender_email=ctx.cfg.get("email_from", ""),
                receiver_email=receiver,
                subject=ctx.cfg.get("email_subject", ""),
                body=ctx.cfg.get("email_body", ""),
                attachment_path=report_path,
                use_tls=ctx.cfg.get("email_use_tls", False),
                use_ssl=ctx.cfg.get("email_use_ssl", False),
                use_auth=ctx.cfg.get("email_use_auth", False),
                username=ctx.cfg.get("email_user", ""),
                password=ctx.cfg.get("email_password", ""),
            )

        # --- Provide Feedback ---
        if success:
            ctx.console.print(f"[green]Report has been sent successfully to {receiver}.[/green]")
        else:
            ctx.console.print("[red]Failed to send the report. Please check the logs for details.[/red]")
