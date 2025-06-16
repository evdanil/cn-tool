import signal
import termios
import sys
import tty
from core.base import ScriptContext


def read_user_input(ctx: ScriptContext, prompt: str = " ", read_pass: bool = False) -> str:
    """
    Read user input and checks for CTRL-D/CTRL-C combinations
    If read_pass is True, function will request password string
    """
    raw_input = ""
    try:
        raw_input = ctx.console.input(f"{prompt}", password=read_pass, markup=True)
    except EOFError:
        # exit_now(logger, cfg, 0)
        pass
    except KeyboardInterrupt:
        interrupt_handler(ctx, signal.SIGINT, None)
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
