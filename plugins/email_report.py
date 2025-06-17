from typing import Dict, Any
from core.base import BaseModule, BasePlugin, ScriptContext
from utils.email_helper import send_report_email


class EmailReportPlugin(BasePlugin):
    """
    A lifecycle plugin that sends the final report via email on application exit.
    """

    @property
    def name(self) -> str:
        return "Email Report on Exit"

    @property
    def target_module_name(self) -> str:
        # This plugin does not target a specific module, but the property is required.
        # We can return an empty string.
        return ""

    @property
    def manages_global_connection(self) -> bool:
        # We set this to True to ensure our `disconnect` method is called on exit.
        return True

    @property
    def user_configurable_settings(self) -> list[Dict[str, str]]:
        return [
            {'key': 'email_enabled', 'prompt': 'Enable Email Feature'},
            {'key': 'email_send_on_exit', 'prompt': 'Send Report on Exit'},
            {'key': 'email_to', 'prompt': 'Recipient Email Address'},
            # {'key': 'email_server', 'prompt': 'SMTP Server'},
        ]

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        """Defines the configuration needed for sending emails."""
        return {
            "email_enabled":      {"section": "email", "ini_key": "enabled", "type": "bool", "fallback": False},
            "email_send_on_exit": {"section": "email", "ini_key": "send_on_exit", "type": "bool", "fallback": False},
            "email_to":           {"section": "email", "ini_key": "to", "type": "str", "fallback": ""},
            "email_from":         {"section": "email", "ini_key": "from", "type": "str", "fallback": "cn-tool@localhost"},
            "email_subject":      {"section": "email", "ini_key": "subject", "type": "str", "fallback": "cn-tool Report"},
            "email_body":         {"section": "email", "ini_key": "body", "type": "str", "fallback": "Please find the attached report."},
            "email_server":       {"section": "email", "ini_key": "server", "type": "str", "fallback": "localhost"},
            "email_port":         {"section": "email", "ini_key": "port", "type": "int", "fallback": 25},
            "email_use_tls":      {"section": "email", "ini_key": "use_tls", "type": "bool", "fallback": False},
            "email_use_ssl":      {"section": "email", "ini_key": "use_ssl", "type": "bool", "fallback": False},
            "email_use_auth":     {"section": "email", "ini_key": "use_auth", "type": "bool", "fallback": False},
            "email_user":         {"section": "email", "ini_key": "user", "type": "str", "fallback": ""},
            "email_password":     {"section": "email", "ini_key": "password", "type": "str", "fallback": ""},
        }

    def register(self, module: BaseModule) -> None:
        """This plugin doesn't interact with modules, so we do nothing here."""
        pass

    def disconnect(self, ctx: ScriptContext) -> None:
        """
        This method is called on application exit. It checks the config and sends the email.
        """
        # Check the new general enabled flag first
        if not ctx.cfg.get("email_enabled"):
            return
        if not ctx.cfg.get("email_send_on_exit"):
            return

        ctx.logger.info("EMAIL: 'send_on_exit' is true. Attempting to email report.")
        with ctx.console.status("[green]Sending report...[/green]", spinner="dots12"):
            # 2. Check if there's a recipient
            receiver = ctx.cfg.get("email_to")
            if not receiver:
                ctx.logger.warning("EMAIL: 'send_on_exit' is true, but no recipient ('to') is configured. Skipping.")
                return

            # 3. Get the report path from the context
            report_path = ctx.cfg.get("report_file")
            if not report_path or not report_path.is_file():
                ctx.logger.warning(f"EMAIL: Report file not found at '{report_path}'. Cannot send email.")
                return

            # 4. Call the helper function with all the config values
            success = send_report_email(
                logger=ctx.logger,
                smtp_server=ctx.cfg.get("email_server", ""),
                smtp_port=int(ctx.cfg.get("email_port", 25)),  # Ensure port is an int
                sender_email=ctx.cfg.get("email_from", ""),
                receiver_email=receiver,
                subject=ctx.cfg.get("email_subject", ""),
                body=ctx.cfg.get("email_body", ""),
                attachment_path=report_path,
                use_tls=ctx.cfg.get("email_use_tls", False),
                use_ssl=ctx.cfg.get("email_use_ssl", False),
            )

        if success:
            ctx.console.print("[green]Report has been sent successfully via email.[/green]")
        else:
            ctx.console.print("[red]Failed to send report via email. Please check the logs.[/red]")
