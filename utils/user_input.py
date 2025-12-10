import termios
import sys
import tty
from typing import Optional, Callable
import threading
from core.base import ScriptContext
from utils.app_lifecycle import exit_now
from utils.display import get_global_color_scheme
from rich.live import Live
from rich.text import Text
from rich.console import Group, Console
import time
import select
import os
try:
    import msvcrt  # type: ignore
except Exception:  # non-Windows
    msvcrt = None


def read_user_input(ctx: ScriptContext, prompt: Optional[str] = " ", read_pass: bool = False) -> str:
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
        ctx.logger.info("CTRL-D (EOF) detected, returning...")
        return raw_input

    except KeyboardInterrupt:
        # User pressed CTRL-C. This is the main fix.
        # We call the new exit_now function, passing the context and the list of
        # plugins that is stored within the context.
        ctx.logger.info("CTRL-C (SIGINT) detected, initiating clean shutdown.")
        exit_now(ctx, 1, "Interrupted by user... Exiting...")

    return raw_input


def read_single_keypress(ctx: ScriptContext) -> str:
    # Save the current terminal settings
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    ch = ''

    try:
        # Switch terminal to raw mode to capture single key press without enter
        tty.setraw(sys.stdin.fileno())

        # Read a single character
        ch = sys.stdin.read(1)

        # Check for Ctrl+C (End of Text character)
        if ch == '\x03':
            # We must restore terminal settings BEFORE exiting, otherwise
            # the user's terminal will be left in a broken state.
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            ctx.logger.info("CTRL-C (SIGINT) detected in single-keypress mode, initiating clean shutdown.")
            exit_now(ctx, 1, "Interrupted by user... Exiting...")

        # Check for Ctrl+D (End of Transmission character)
        if ch == '\x04':
            # Restore terminal settings before exiting
            # termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            ctx.logger.info("CTRL-D (EOF) detected in single-keypress mode, returning normally")

    finally:
        # Restore the terminal settings
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    return ch


def press_any_key(ctx: ScriptContext) -> None:
    """  Prints press any key message and read single press of any key
    """
    colors = get_global_color_scheme(ctx.cfg)
    ctx.console.print(f"[{colors['description']}]Press [{colors['error']}]any[/] key to continue[/]")
    read_single_keypress(ctx)


def read_user_input_live(
    ctx: ScriptContext,
    render: Callable[[], str],
    indexing_active: bool = False,
    refresh_signal: Optional[threading.Event] = None,
) -> str:
    """
    Live-updating menu with a keystroke-buffered prompt inside the Live area.
    - Shows typed characters as you enter them.
    - Supports Backspace, Enter, and Esc to clear.
    - Keeps the status/menu refreshing until you press Enter.

    Optimized to minimize CPU usage:
    - Caches parsed Rich objects (avoids markup reparsing)
    - Tracks state to detect real changes
    - Uses minute-boundary detection for timestamp updates
    - Adaptive refresh intervals (2.5s during indexing, 60s when idle)

    refresh_signal allows external events to trigger an immediate refresh
    without waiting for the next scheduled interval.
    """
    from datetime import datetime

    colors = get_global_color_scheme(ctx.cfg)
    buffer: str = ""
    is_windows = os.name == 'nt' or (sys.platform.startswith('win'))

    # POSIX: set raw mode; Windows: use msvcrt
    fd = None
    old_settings = None
    restored = False
    if not is_windows:
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        # Enter a cbreak-like mode: disable canonical input and echo, keep output processing intact
        new_settings = termios.tcgetattr(fd)
        new_settings[3] = new_settings[3] & ~(termios.ICANON | termios.ECHO)
        # Disable software flow control so we can handle CTRL-S/CTRL-Q ourselves
        new_settings[0] = new_settings[0] & ~(termios.IXON | termios.IXOFF)
        new_settings[6][termios.VMIN] = 1
        new_settings[6][termios.VTIME] = 0
        termios.tcsetattr(fd, termios.TCSANOW, new_settings)

    # Use a dedicated Rich Console with force_terminal=True so Live updates in-place
    live_console = Console(theme=getattr(ctx.console, 'theme', None), force_terminal=True)
    got_kbint = False
    try:
        # Initialize state tracking
        status_header = render().rstrip()
        current_minute = datetime.now().minute

        # State dict to track what changed
        state = {
            'status_header': status_header,
            'buffer': buffer,
            'minute': current_minute,
            'was_indexing': indexing_active,  # Track indexing state changes
        }

        # Parse components once (cached Rich objects)
        status_text = Text.from_markup(status_header)
        prompt_text = Text.from_markup(f"\n\n[{colors['description']}]Enter your choice:[/] ")

        # Compose initial frame from cached objects
        initial_group = Group(status_text, prompt_text)

        # Initial interval based on current indexing state
        status_refresh_interval = 2.5 if indexing_active else 60.0
        next_status_at = time.monotonic() + max(0.5, status_refresh_interval)

        # Base polling windows (used mainly on Windows path)
        poll_active = 0.10  # when user is actively typing (last 2s)
        poll_idle = 0.30    # relaxed polling when idle
        last_key_time: float = 0.0  # 0 => no recent typing

        with Live(initial_group, console=live_console, screen=True, refresh_per_second=1) as live:
            updates_paused = False
            while True:
                # Check current indexing state dynamically (it can change mid-loop!)
                try:
                    current_indexing = bool(ctx.cache and ctx.cache.dc and ctx.cache.dc.get("indexing", False))
                except Exception:
                    current_indexing = False

                # Recalculate interval based on CURRENT state
                status_refresh_interval = 2.5 if current_indexing else 60.0

                # Detect indexing state transition
                if current_indexing != state.get('was_indexing', False):
                    # State changed! Adjust next wakeup immediately
                    state['was_indexing'] = current_indexing
                    if current_indexing:
                        # Just started indexing - wake up sooner
                        next_status_at = time.monotonic() + 0.1  # Wake almost immediately
                    else:
                        # Indexing stopped - can relax
                        next_status_at = time.monotonic() + status_refresh_interval

                now = time.monotonic()
                now_dt = datetime.now()
                current_minute = now_dt.minute

                forced_refresh = False
                if refresh_signal is not None and refresh_signal.is_set():
                    forced_refresh = True
                    refresh_signal.clear()

                # Check if we need to refresh status (interval elapsed OR minute changed)
                status_needs_refresh = (not updates_paused) and (
                    forced_refresh or (now >= next_status_at) or (current_minute != state['minute'])
                )

                if status_needs_refresh:
                    new_header = render().rstrip()
                    if new_header != state['status_header']:
                        state['status_header'] = new_header
                        status_text = Text.from_markup(new_header)
                    state['minute'] = current_minute
                    # Use current dynamic interval
                    next_status_at = now + max(0.5, status_refresh_interval)

                # Check if buffer changed
                buffer_changed = buffer != state['buffer']
                if buffer_changed:
                    state['buffer'] = buffer
                    prompt_text = Text.from_markup(f"\n\n[{colors['description']}]Enter your choice:[/] {buffer}")

                # Only update Live display if something actually changed
                if (status_needs_refresh or buffer_changed) and not updates_paused:
                    live.update(Group(status_text, prompt_text), refresh=True)

                try:
                    if is_windows and msvcrt:
                        # Poll keyboard
                        if msvcrt.kbhit():
                            ch = msvcrt.getwch()
                            # Handle special keys (arrows etc.) which come as \xe0 or \x00 prefix
                            if ch in ('\x00', '\xe0'):
                                _ = msvcrt.getwch()  # consume the next char
                                continue
                            if ch == '\x13':  # CTRL-S pauses refresh
                                if not updates_paused:
                                    updates_paused = True
                                    live.stop(refresh=False)
                                    ctx.console.print(Group(status_text, prompt_text))
                                    ctx.console.print(f"\n[{colors['description']}]Menu updates paused. Press CTRL-Q to resume.[/]")
                                continue
                            if ch == '\x11':  # CTRL-Q resumes refresh
                                if updates_paused:
                                    updates_paused = False
                                    ctx.console.clear()
                                    # Refresh menu when coming back
                                    refreshed_header = render().rstrip()
                                    status_text = Text.from_markup(refreshed_header)
                                    state['status_header'] = refreshed_header
                                    state['minute'] = datetime.now().minute
                                    prompt_text = Text.from_markup(f"\n\n[{colors['description']}]Enter your choice:[/] {buffer}")
                                    live.start()
                                    live.update(Group(status_text, prompt_text), refresh=True)
                                    next_status_at = time.monotonic() + max(0.5, status_refresh_interval)
                                continue
                            if ch in ('\r', '\n'):
                                return buffer.strip()
                            if ch == '\x08':  # Backspace
                                buffer = buffer[:-1]
                                last_key_time = time.monotonic()
                                continue
                            if ch == '\x1b':  # ESC clears buffer
                                buffer = ""
                                last_key_time = time.monotonic()
                                continue
                            # Printable char
                            buffer += ch
                            last_key_time = time.monotonic()
                        else:
                            # Calculate optimal sleep: either next status update or next minute boundary
                            now2 = time.monotonic()
                            sleep_for = max(0.0, next_status_at - now2)

                            # Also consider minute boundary for timestamp updates
                            now_dt = datetime.now()
                            seconds_until_next_minute = 60 - now_dt.second
                            sleep_for = min(sleep_for, seconds_until_next_minute)

                            # Cap at 2.5s max to detect indexing state changes within reasonable time
                            sleep_for = min(sleep_for, 2.5)

                            # Adaptive polling based on recent typing activity (2s window)
                            typing_active = (last_key_time > 0.0) and ((now2 - last_key_time) < 2.0)
                            current_poll = poll_active if typing_active else poll_idle
                            time.sleep(min(current_poll, sleep_for))
                    else:
                        # POSIX: select on stdin
                        # Block until either input arrives, next status update, or next minute boundary
                        now_mono = time.monotonic()
                        timeout_status = max(0.0, next_status_at - now_mono)

                        # Calculate seconds until next minute boundary for timestamp updates
                        now_dt = datetime.now()
                        seconds_until_next_minute = 60 - now_dt.second
                        timeout = min(timeout_status, seconds_until_next_minute)

                        # Cap at 2.5s max to detect indexing state changes within reasonable time
                        # This ensures we loop back and check current_indexing at least every 2.5s
                        timeout = min(timeout, 2.5)

                        r, _, _ = select.select([sys.stdin], [], [], timeout)
                        if r:
                            ch = sys.stdin.read(1)
                            if ch == '\x13':  # CTRL-S pauses refresh
                                if not updates_paused:
                                    updates_paused = True
                                    live.stop(refresh=False)
                                    ctx.console.print(Group(status_text, prompt_text))
                                    ctx.console.print(f"\n[{colors['description']}]Menu updates paused. Press CTRL-Q to resume.[/]")
                                continue
                            if ch == '\x11':  # CTRL-Q resumes refresh
                                if updates_paused:
                                    updates_paused = False
                                    ctx.console.clear()
                                    refreshed_header = render().rstrip()
                                    status_text = Text.from_markup(refreshed_header)
                                    state['status_header'] = refreshed_header
                                    state['minute'] = datetime.now().minute
                                    prompt_text = Text.from_markup(f"\n\n[{colors['description']}]Enter your choice:[/] {buffer}")
                                    live.start()
                                    live.update(Group(status_text, prompt_text), refresh=True)
                                    next_status_at = time.monotonic() + max(0.5, status_refresh_interval)
                                continue
                            if ch in ('\r', '\n'):
                                return buffer.strip()
                            if ch in ('\x7f', '\b', '\x08'):  # Backspace variants
                                buffer = buffer[:-1]
                                last_key_time = time.monotonic()
                                continue
                            if ch == '\x1b':
                                # Try to consume the rest of an escape sequence non-blocking
                                # or treat ESC as clear buffer
                                time.sleep(0.01)
                                if select.select([sys.stdin], [], [], 0)[0]:
                                    _ = sys.stdin.read(2)  # likely '[' + code
                                else:
                                    buffer = ""  # lone ESC clears
                                last_key_time = time.monotonic()
                                continue
                            # Otherwise append printable characters
                            if ch.isprintable():
                                buffer += ch
                                last_key_time = time.monotonic()
                        # else: timeout reached; loop will refresh status on next iteration
                except EOFError:
                    # CTRL-D or similar: treat as empty submit
                    return buffer.strip()
                except KeyboardInterrupt:
                    # Defer printing until after Live has exited and terminal restored
                    ctx.cfg["exiting"] = True
                    got_kbint = True
                    break
    finally:
        if not is_windows and fd is not None and old_settings is not None and not restored:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            restored = True
    if got_kbint:
        # After closing Live, ensure terminal restored, clear and print a clean final view
        try:
            if not is_windows and fd is not None and old_settings is not None and not restored:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                restored = True
        except Exception:
            pass
        try:
            ctx.console.clear()
            # Re-render one final static view (now that exiting flag is set)
            final_view = render()
            ctx.console.print(final_view)
            colors = get_global_color_scheme(ctx.cfg)
            ctx.console.print(f"\n[{colors['error']}]Interrupted by user... Exiting gracefully...[/]")
        except Exception:
            pass
        ctx.logger.info("CTRL-C (SIGINT) detected, initiating clean shutdown.")
        exit_now(ctx, 1, "Interrupted by user... Exiting...")
        return ""
    return buffer.strip()

