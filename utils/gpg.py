import logging
import subprocess
from typing import Optional, Tuple
from pathlib import Path
from core.base import ScriptContext
from utils.file_io import check_file_accessibility, check_file_timeliness


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


def get_gpg_credentials(ctx: ScriptContext) -> Optional[Tuple[str, str]]:
    """Main function to get decrypted GPG credentials."""
    file_path: Path = ctx.cfg["gpg_credentials"]
    if not check_file_accessibility(ctx.logger, file_path) or not check_file_timeliness(ctx.logger, file_path):
        return None

    decrypted_output = decrypt_gpg_file(ctx.logger, file_path)
    return parse_gpg_credentials(decrypted_output) if decrypted_output else None
