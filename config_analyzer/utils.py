import os
from typing import Optional, List

from .parser import parse_snapshot, Snapshot


def safe_call(func, *args, **kwargs):
    """Safely call a function, ignoring exceptions."""
    try:
        return func(*args, **kwargs)
    except Exception:
        pass
    return None


def handle_search_key(app, event, search_target):
    """Common search key handling logic.

    Returns True if the key was handled, False otherwise.
    """
    k = event.key
    ch = getattr(event, "character", "") or ""

    # Map keys to their corresponding actions
    actions = {
        "escape": "action_cancel_find",
        "down": "action_find_next",
        "up": "action_find_prev",
        "enter": "action_find_next",
        "return": "action_find_next",
        "backspace": "action_find_backspace",
        "ctrl+h": "action_find_backspace",
        "\b": "action_find_backspace",
    }

    # Check if we can handle this key
    if k in actions:
        safe_call(getattr(app, actions[k]))
        safe_call(event.stop)
        return True

    # Handle printable characters
    if (isinstance(ch, str) and len(ch) == 1 and ch.isprintable() and
        not any(getattr(event, mod, False) for mod in ["ctrl", "alt", "meta"])):
        safe_call(app.action_find_append_char, ch)
        safe_call(event.stop)
        return True

    return False


def find_device_history(repo_root: str, device: str, cfg_path: Optional[str], history_dir: str) -> Optional[str]:
    """Locate the nearest 'history/<device>' directory.

    Preference order:
    - Closest ancestor of the provided cfg_path
    - Repo root history folder
    - Any discovered 'history/<device>' path in the repo (shortest path)
    """
    history_dir_l = str(history_dir).lower()
    # Prefer nearest 'history/<device>' relative to the selected cfg directory, walking up to repo root
    if cfg_path:
        repo_abs = os.path.abspath(repo_root)
        cur = os.path.dirname(os.path.abspath(cfg_path))
        while True:
            cand = os.path.join(cur, history_dir, device)
            if os.path.isdir(cand):
                return cand
            if os.path.abspath(cur) == repo_abs:
                break
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    # Fallback 1: repo root history
    cand = os.path.join(repo_root, history_dir, device)
    if os.path.isdir(cand):
        return cand
    # Fallback 2: scan repo for any 'history/<device>' path; pick shortest path
    hits: List[str] = []
    for root, dirs, _files in os.walk(repo_root):
        if any(d.lower() == history_dir_l for d in dirs):
            path = os.path.join(root, history_dir, device)
            if os.path.isdir(path):
                hits.append(path)
    if hits:
        hits.sort(key=lambda p: len(p))
        return hits[0]
    return None


def collect_snapshots(repo_root: str, device: str, selected_cfg_path: Optional[str], history_dir: str) -> List[Snapshot]:
    """Collect snapshots for a device including current config.

    - Finds current config outside history (using selected path if provided)
    - Discovers history snapshots under nearest history folder
    - Parses, orders by timestamp desc, ensures 'Current' first when present
    - Drops 'Current' if content equals the latest snapshot to reduce duplication
    """
    snapshots: List[Snapshot] = []

    # Determine current config path
    current_config_path: Optional[str] = None
    if selected_cfg_path:
        current_config_path = selected_cfg_path
    else:
        history_dir_l = str(history_dir).lower()
        for root, dirs, files in os.walk(repo_root):
            # prune any history directories from traversal
            dirs[:] = [d for d in dirs if d.lower() != history_dir_l]
            if f"{device}.cfg" in files:
                current_config_path = os.path.join(root, f"{device}.cfg")
                break

    if current_config_path:
        cur = parse_snapshot(current_config_path)
        if cur:
            cur = cur._replace(original_filename="Current")
            snapshots.append(cur)

    # History snapshots
    hist_dir = find_device_history(repo_root, device, selected_cfg_path, history_dir)
    if hist_dir and os.path.isdir(hist_dir):
        for f in sorted(os.listdir(hist_dir)):
            full = os.path.join(hist_dir, f)
            if os.path.isfile(full) and f.lower().endswith('.cfg'):
                snap = parse_snapshot(full)
                if snap:
                    snapshots.append(snap)

    # Split Current vs others
    current_item: Optional[Snapshot] = None
    others: List[Snapshot] = []
    for s in snapshots:
        if s.original_filename == "Current" and current_item is None:
            current_item = s
        else:
            others.append(s)

    others.sort(key=lambda s: s.timestamp, reverse=True)

    # If Current equals the latest snapshot content-wise, drop it to avoid duplication
    if current_item and others:
        latest = others[0]
        try:
            if getattr(current_item, "content_body", "") == getattr(latest, "content_body", None):
                current_item = None
        except Exception:
            pass

    return ([current_item] if current_item else []) + others

