from pathlib import Path
import hashlib


def calculate_config_hash(file_path: Path) -> str:
    """
    Calculates the SHA256 hash of a config file, ignoring comment lines
    and other volatile headers.
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:  # Open in binary mode for hashing
            for line in f:
                # Decode for checking, but hash the original bytes
                line_str = line.decode('utf-8', errors='ignore').strip()
                # Skip common volatile lines
                if line_str.startswith(('!', '---', 'Building configuration...', 'Current configuration', '#')) or not line_str:
                    continue
                hasher.update(line)
    except (IOError, OSError):
        # Return a non-matching hash if file can't be read
        return "error-generating-hash"
    return hasher.hexdigest()
