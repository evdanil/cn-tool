import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Tuple
from pathlib import Path
from core.base import ScriptContext
from utils.file_io import check_file_accessibility, check_file_timeliness


@dataclass(frozen=True)
class GpgRead:
    """What one read of a GPG credentials file gave: the pair, or the first problem.

    ``problem`` is "" when both lines were read; else one of "is not set", "cannot be read",
    "is older than 24 h" (only with ``check_age``), "could not be decrypted by gpg --batch" and
    "has no User = or Password = line". The password is not part of ``repr``.
    """
    user: str = ""
    password: str = field(default="", repr=False)
    problem: str = ""


def decrypt_gpg_file(logger: logging.Logger, file_path: Path) -> Optional[str]:
    """Attempt to decrypt the GPG file and handle possible subprocess exceptions."""
    try:
        result = subprocess.run(
            ["gpg", "--batch", "-d", file_path],
            capture_output=True, text=True, check=True, timeout=90
        )
        return result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        logger.error(f"Unable to decrypt {file_path} - {e}")
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
    """
    if file_path is None:
        return GpgRead(problem="is not set")
    if not check_file_accessibility(logger, file_path):
        return GpgRead(problem="cannot be read")
    if check_age and not check_file_timeliness(logger, file_path):
        return GpgRead(problem="is older than 24 h")

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
