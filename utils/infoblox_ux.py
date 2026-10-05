from __future__ import annotations


def format_no_match_message(resource_label: str, query: str) -> str:
    """Return a consistent no-result message for Infoblox-backed lookups."""
    text = str(query or "").strip()
    if text:
        return f"No matching {resource_label} found for '{text}'."
    return f"No matching {resource_label} found."


def format_partial_results_message(message: str) -> str:
    """Return a consistent partial-results warning message."""
    return f"Partial Infoblox results: {message}"
