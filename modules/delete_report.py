from typing import Optional
from core.base import BaseModule, ScriptContext
from utils.file_io import clear_report
from utils.user_input import press_any_key


class DeleteReportModule(BaseModule):
    """
    A simple module to trigger the deletion of the report file.
    """

    @property
    def menu_key(self) -> str:
        """The character key to trigger this module from the menu."""
        return "d"

    @property
    def menu_title(self) -> str:
        """The title of the module to display in the menu."""
        return "Delete Report"

    @property
    def visibility_config_key(self) -> Optional[str]:
        return None

    def run(self, ctx: ScriptContext) -> None:
        """Calls the utility function to clear the report."""
        ctx.logger.info("Request Type - Delete Report")
        # The clear_report function already provides user feedback.
        clear_report(ctx)

        press_any_key(ctx)
