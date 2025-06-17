import termios
import sys
import tty
from core.base import ScriptContext
from utils.app_lifecycle import exit_now


def read_user_input(ctx: ScriptContext, prompt: str = " ", read_pass: bool = False) -> str:
    """
    Read user input and gracefully handle CTRL-C (KeyboardInterrupt) and
    CTRL-D (EOFError) to ensure a clean application shutdown.

    If read_pass is True, function will request a password string.
    """
    raw_input = ""
    try:
        raw_input = ctx.console.input(f"{prompt}", password=read_pass, markup=True)

    except EOFError:
        # User pressed CTRL-D. This should also trigger a clean exit.
        # We have access to everything we need via the context.
        ctx.logger.info("CTRL-D (EOF) detected, initiating clean shutdown.")
        exit_now(ctx, 0, "Exiting...")

    except KeyboardInterrupt:
        # User pressed CTRL-C. This is the main fix.
        # We call the new exit_now function, passing the context and the list of
        # plugins that is stored within the context.
        ctx.logger.info("CTRL-C (SIGINT) detected, initiating clean shutdown.")
        exit_now(ctx, 1, "Interrupted by user... Exiting...")

    return raw_input


def read_single_keypress() -> str:
    # Save the current terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        # Switch terminal to raw mode to capture single key press without enter
        tty.setraw(sys.stdin.fileno())

        # Read a single character
        ch = sys.stdin.read(1)
    finally:
        # Restore the terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return ch
