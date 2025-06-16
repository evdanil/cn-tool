# modules/demob_check.py
from core.base import BaseModule, ScriptContext
from utils.user_input import read_user_input
from utils.validation import is_valid_site
from utils.display import console, get_global_color_scheme

# Import the module class itself, not an instance
from .config_search import ConfigSearchModule

class DemobCheckModule(BaseModule):
    # This module needs the config repo because it calls the search module
    requires_config_repo = True

    @property
    def menu_key(self) -> str:
        return "8"

    @property
    def menu_title(self) -> str:
        return "Site Demobilization Check"

    def run(self, ctx: ScriptContext):
        """
        Handles the user-facing part of the demobilization check.
        It prompts for input and then calls the backend search logic.
        """
        colors = get_global_color_scheme(ctx.cfg)

        # Step 1: Display prompt and get user input
        console.print(
            "\n"
            f"[{colors['warning']} {colors['bold']}]This request is to verify if any subnets for a given sitecode exist on devices.[/]\n"
            f"[{colors['description']}]Type in location site code to perform search.[/]\n"
            f"[{colors['description']}]Supported site code format: [{colors['success']} {colors['bold']}]XXX, XXXXXXX, XXX-XX\\[XX][/]\n"
        )
        raw_input = read_user_input(ctx, "Enter location site code: ").strip()

        # Step 2: Validate the user's input
        if not is_valid_site(raw_input):
            ctx.logger.info(f"User input - Incorrect site code {raw_input}")
            console.print(f"[{colors['error']}]Incorrect site code[/]")
            return

        sitecode = raw_input.upper()

        # Step 3: Instantiate the search module and call its public method
        # This is where the handoff from the "UI" module to the "logic" module happens.
        search_engine = ConfigSearchModule()
        search_engine.execute_demob_search(ctx, sitecode)