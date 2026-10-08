import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Tuple
from pathlib import Path
from cn_tool.core.base import ScriptContext
from cn_tool.utils import oscompat
from cn_tool.utils.file_io import check_file_accessibility, check_file_timeliness

# The problem of a Windows host without gpg on PATH: it names the fix (Gpg4win installs gpg.exe, and a terminal
# that was open before the install does not see the new PATH).
GPG_NOT_INSTALLED = "could not be decrypted: gpg is not installed (install Gpg4win, then open a new terminal)"

# Windows PowerShell 5.1 saves ``Set-Content -Encoding utf8`` and ``Out-File -Encoding utf8`` with a UTF-8 byte-order
# mark. gpg returns it as the first character of the text, where it would hide the first line's "User =".
_BYTE_ORDER_MARK = "\ufeff"


@dataclass(frozen=True)
class GpgRead:
    """What one read of a GPG credentials file gave: the pair, or the first problem.

    ``problem`` is "" when both lines were read; else one of "is not set", "cannot be read",
    "is older than 24 h" (only with ``check_age``), "could not be decrypted by gpg --batch" (gpg failed, timed
    out, was not found, or printed text that is not UTF-8), on Windows without gpg on PATH GPG_NOT_INSTALLED,
    and "has no User = or Password = line". The password is not part of ``repr``.
    """
    user: str = ""
    password: str = field(default="", repr=False)
    problem: str = ""


def decrypt_gpg_file(logger: logging.Logger, file_path: Path) -> Optional[str]:
    """Attempt to decrypt the GPG file and handle possible subprocess exceptions.

    The output is read as UTF-8, not in the locale's encoding (cp1252 on Windows). Text that is not UTF-8
    (a credentials file written by PowerShell 5.1's ``>`` is UTF-16) is a failure like any other: the log
    says so, and the caller reports "could not be decrypted".

    A UTF-8 byte-order mark at the very start of the text is dropped (a file saved by Windows PowerShell 5.1 has
    one); a mark anywhere else is part of the text.

    The bytes that are not UTF-8 are kept as lone surrogates (``errors="surrogateescape"``) and found by
    encoding the text again. A strict decode would raise inside ``subprocess`` instead, and on Windows that
    happens in a reader thread: the exception is printed to stderr as a thread traceback and ``run`` returns
    no output at all.
    """
    try:
        result = subprocess.run(
            ["gpg", "--batch", "-d", file_path],
            capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", check=True, timeout=90
        )
        output = result.stdout
        output.encode("utf-8")  # raises for what surrogateescape kept of bytes that are not UTF-8
        return output.removeprefix(_BYTE_ORDER_MARK)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error(f"Unable to decrypt {file_path} - {e}")
        return None
    except (UnicodeDecodeError, UnicodeEncodeError):
        # The exception is not logged: its text names a byte of the decrypted file, which holds a password.
        logger.error(
            f"Unable to decrypt {file_path} - the output is not UTF-8 text; encrypt a plain text file saved as UTF-8"
        )
        return None


def parse_gpg_credentials(gpg_output: str) -> Optional[Tuple[str, str]]:
    """Parse decrypted GPG output to extract user and password."""
    user = password = None
    for line in gpg_output.splitlines():
        if line.startswith("User ="):
            user = line.split("=", 1)[1].strip()
        elif line.startswith("Password ="):
            password = line.split("=", 1)[1].strip()
    return (user, password) if user and password else None


def read_gpg_file(logger: logging.Logger, file_path: Optional[Path], *, check_age: bool = True) -> GpgRead:
    """Read a GPG credentials file once: the pair, or the first problem and why.

    The checks run in the order they always did (readable, then not older than 24 h, then decrypted, then
    parsed); the first that fails names its reason. A None path is "is not set". A file that cannot be
    read, or is too old, never runs gpg. ``check_age=False`` skips the 24 h rule (the Infoblox file has
    none). The reasons are return values, not new log lines.

    On Windows only, gpg is looked up on PATH before it is run (Gpg4win puts ``gpg.exe`` there): without it
    the problem is GPG_NOT_INSTALLED, which says what to install. POSIX runs gpg and keeps its own problem.
    """
    if file_path is None:
        return GpgRead(problem="is not set")
    if not check_file_accessibility(logger, file_path):
        return GpgRead(problem="cannot be read")
    if check_age and not check_file_timeliness(logger, file_path):
        return GpgRead(problem="is older than 24 h")
    if oscompat.is_windows() and shutil.which("gpg") is None:
        return GpgRead(problem=GPG_NOT_INSTALLED)

    decrypted_output = decrypt_gpg_file(logger, file_path)
    if decrypted_output is None:
        return GpgRead(problem="could not be decrypted by gpg --batch")
    parsed = parse_gpg_credentials(decrypted_output)
    if parsed is None:
        return GpgRead(problem="has no User = or Password = line")
    return GpgRead(user=parsed[0], password=parsed[1])


def get_gpg_credentials(ctx: ScriptContext) -> Optional[Tuple[str, str]]:
    """The device credentials file (``[gpg] credentials``, ignored when older than 24 h) as a pair, or None."""
    result = read_gpg_file(ctx.logger, ctx.cfg["gpg_credentials"])
    return None if result.problem else (result.user, result.password)
