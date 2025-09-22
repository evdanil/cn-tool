from typing import Any, Dict

from core.base import BaseModule, BasePlugin, ScriptContext
from utils.email_helper import interpret_bool, send_configured_report


class EmailReportPlugin(BasePlugin):
    """Lifecycle plugin that emails the final report when the application exits."""

    @property
    def name(self) -> str:
        return "Email Support"

    @property
    def target_module_name(self) -> str:
        return ""

    @property
    def manages_global_connection(self) -> bool:
        return True

    @property
    def user_configurable_settings(self) -> list[Dict[str, str]]:
        return [
            {'key': 'email_enabled', 'prompt': 'Enable Email Feature'},
            {'key': 'email_send_on_exit', 'prompt': 'Send Report on Exit'},
            {'key': 'email_delete_after_send', 'prompt': 'Delete report on successful email action'},
            {'key': 'email_to', 'prompt': 'Recipient Email Address'},
            # {'key': 'email_server', 'prompt': 'SMTP Server'},
        ]

    @property
    def config_schema(self) -> Dict[str, Dict[str, Any]]:
        return {
            "email_enabled":             {"section": "email", "ini_key": "enabled", "type": "bool", "fallback": False},
            "email_send_on_exit":        {"section": "email", "ini_key": "send_on_exit", "type": "bool", "fallback": False},
            "email_delete_after_send":   {"section": "email", "ini_key": "delete_after_send", "type": "bool", "fallback": False},
            "email_to":                  {"section": "email", "ini_key": "to", "type": "str", "fallback": ""},
            "email_from":                {"section": "email", "ini_key": "from", "type": "str", "fallback": "cn-tool@localhost"},
            "email_subject":             {"section": "email", "ini_key": "subject", "type": "str", "fallback": "cn-tool Report"},
            "email_body":                {"section": "email", "ini_key": "body", "type": "str", "fallback": "Please find the attached report."},
            "email_server":              {"section": "email", "ini_key": "server", "type": "str", "fallback": "localhost"},
            "email_port":                {"section": "email", "ini_key": "port", "type": "int", "fallback": 25},
            "email_use_tls":             {"section": "email", "ini_key": "use_tls", "type": "bool", "fallback": False},
            "email_use_ssl":             {"section": "email", "ini_key": "use_ssl", "type": "bool", "fallback": False},
            "email_use_auth":            {"section": "email", "ini_key": "use_auth", "type": "bool", "fallback": False},
            "email_user":                {"section": "email", "ini_key": "user", "type": "str", "fallback": ""},
            "email_password":            {"section": "email", "ini_key": "password", "type": "str", "fallback": ""},
        }

    def register(self, module: BaseModule) -> None:
        pass

    def disconnect(self, ctx: ScriptContext) -> None:
        if not interpret_bool(ctx.cfg.get("email_enabled")):
            return
        if not interpret_bool(ctx.cfg.get("email_send_on_exit")):
            return

        ctx.logger.info("EMAIL: 'send_on_exit' is true. Attempting to email report.")
        with ctx.console.status("[green]Sending report...[/green]", spinner="dots12"):
            send_configured_report(
                ctx,
                report_path=ctx.cfg.get("report_file"),
                receiver=ctx.cfg.get("email_to"),
                prefix="EMAIL",
                success_message="[green]Report has been sent successfully via email.[/green]",
                failure_message="[red]Failed to send report via email. Please check the logs.[/red]",
            )
