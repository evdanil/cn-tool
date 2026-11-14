"""``py -m cn_tool.webui --create-shortcut``: Start Menu and Desktop shortcuts to the signed interpreter.

pip's ``Scripts\\cn-web.exe`` is an unsigned launcher stub that application control flags or blocks, so the
shortcuts start ``pythonw.exe -m cn_tool.webui`` (``--console``: ``python.exe``) beside the running interpreter;
in a venv that is the venv's own redirector, so the shortcut stays in the venv (plan
``docs/plans/2026-11-13-windows-signed-launch-plan.md``, section 1.1).

``plan_shortcut`` is pure: it works on ``PureWindowsPath`` and asks an injected ``exists``, so a Linux test uses
real Windows paths. ``create_shortcuts`` is what the launcher calls once its own checks (the options, the
``import nicegui``) have passed. It reaches the shell through ``winshell``'s module attributes and the disk
through ``_exists``.

Both shortcuts show the package's own icon, ``assets/cn-tool.ico`` beside this module (built by
``scripts/build_webui_icon.py``). An installation without that file gets shortcuts with the interpreter's icon.
"""
from __future__ import annotations

import ntpath
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Callable, Optional, TextIO, Union

from cn_tool.utils import oscompat
from cn_tool.webui import winshell

LINK_NAME = "cn-tool Web.lnk"
DESCRIPTION = "cn-tool web interface"

_PREFIX = "cn-web: "
_NOT_WINDOWS = "Shortcuts are created on Windows only. Start the interface with: python -m cn_tool.webui"
_FOLDERS = (("Start Menu", winshell.FOLDERID_PROGRAMS), ("Desktop", winshell.FOLDERID_DESKTOP))
_LABEL_WIDTH = len("Start Menu:")
_SAME_SESSION = ("Starting it again while it runs reopens the same session. "
                 "Quit it with Quit application in the browser.")
_NOTE = "The shortcut starts the web interface without a console window. " + _SAME_SESSION
_CONSOLE_NOTE = ("The shortcut starts the web interface in a console window; closing that window or Ctrl+C "
                 "stops it. " + _SAME_SESSION)


@dataclass(frozen=True)
class Plan:
    """What both shortcuts hold."""

    target: str
    arguments: str
    workdir: str
    description: str
    link_name: str
    icon: Optional[str] = None


@dataclass(frozen=True)
class Refusal:
    """Why no shortcut can be made, as a sentence for stderr (without the ``cn-web:`` prefix)."""

    message: str


def plan_shortcut(
    executable: Optional[str],
    *,
    console: bool,
    config_file: Optional[str],
    home: str,
    cwd: str,
    exists: Callable[[str], bool],
    icon_file: Optional[str] = None,
) -> Union[Plan, Refusal]:
    """The shortcut for the interpreter ``executable`` (``sys.executable``), or why there can be none.

    A relative ``config_file`` is resolved against ``cwd`` and a leading ``~`` against ``home``, as the start
    path reads ``-c``, so the shortcut opens the file the user just named. The configuration file is checked
    first, then the interpreter (plan 1.1, refusals 4 and 5). ``icon_file`` becomes the shortcut's icon when
    it exists; a missing one is no refusal, the shortcut then shows the interpreter's icon.
    """
    arguments = ["-m", "cn_tool.webui"]
    if config_file:
        config = _absolute(os.fspath(config_file), home=home, cwd=cwd)
        if not exists(config):
            return Refusal(f'The configuration file "{config}" does not exist.')
        arguments += ["-c", config]
    if not executable:
        return Refusal("This Python does not report its own path, so a shortcut to it cannot be made.")
    target = str(PureWindowsPath(executable).parent / ("python.exe" if console else "pythonw.exe"))
    if not exists(target):
        if console:
            return Refusal(f"{target} does not exist, so a shortcut that opens a console window cannot be made.")
        return Refusal(f"{target} does not exist, so a shortcut without a console window cannot be made. "
                       "Add --console for a shortcut that opens a console window.")
    return Plan(
        target=target, arguments=subprocess.list2cmdline(arguments), workdir=str(PureWindowsPath(home)),
        description=DESCRIPTION, link_name=LINK_NAME,
        icon=icon_file if icon_file and exists(icon_file) else None,
    )


def create_shortcuts(*, console: bool, config_file: Optional[str], out: TextIO, err: TextIO) -> int:
    """Write the Start Menu shortcut, then the Desktop one, and say what was written. The exit code.

    2: refused (not Windows, a missing configuration file or interpreter), nothing written, the reason on
    ``err``. 3: a folder or a shortcut could not be written; the reason on ``err``, and the shortcuts already
    written are still listed on ``out``. 0: both written, each listed with ``(written)`` or ``(replaced)``,
    then a note on how the shortcut starts and stops.
    """
    if not oscompat.is_windows():
        print(_PREFIX + _NOT_WINDOWS, file=err)
        return 2
    plan = plan_shortcut(
        sys.executable, console=console, config_file=config_file, home=str(Path.home()), cwd=os.getcwd(),
        exists=_exists, icon_file=_icon_file(),
    )
    if isinstance(plan, Refusal):
        print(_PREFIX + plan.message, file=err)
        return 2
    for label, folder_id in _FOLDERS:
        try:
            path = str(PureWindowsPath(winshell.known_folder(folder_id)) / plan.link_name)
            existed = _exists(path)
            winshell.write_link(path, plan.target, plan.arguments, plan.workdir, plan.description,
                                icon=plan.icon)
        except OSError as exc:
            print(f"{_PREFIX}The {label} shortcut could not be written: {exc}", file=err)
            return 3
        print(f"{label + ':':<{_LABEL_WIDTH}} {path} ({'replaced' if existed else 'written'})", file=out)
    print(_CONSOLE_NOTE if console else _NOTE, file=out)
    return 0


def _absolute(config_file: str, *, home: str, cwd: str) -> str:
    path = PureWindowsPath(config_file)
    if not path.drive and not path.root and path.parts[:1] == ("~",):
        path = PureWindowsPath(home, *path.parts[1:])
    return ntpath.normpath(str(PureWindowsPath(cwd) / path))


def _icon_file() -> str:
    """Where the installed package keeps the shortcut's icon. Tests replace this."""
    return str(Path(__file__).resolve().parent / "assets" / "cn-tool.ico")


def _exists(path: str) -> bool:
    """Whether ``path`` is an existing file. Tests replace this with a fake disk."""
    return os.path.isfile(path)
