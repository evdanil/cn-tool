import ipaddress
import re
from typing import Dict, FrozenSet, List, Set

# You might need to import these from your keywords.py file
# from ..keywords import standard_keywords

# Assuming keywords.py is at the root level for now
# If you move it, adjust the import path.
from wordlists.keywords import standard_keywords
from utils.validation import ip_regexp

# P3 Optimization: Module-level compiled regex for word cleanup
# Compiled once at module load instead of per-call
WORD_CLEANUP_PATTERN: re.Pattern = re.compile(r"[\W_]+")
NOISE_TOKEN_RE: re.Pattern = re.compile(r"^(?:[0-9a-f]{24,}|[0-9a-z+/=]{40,})$", re.IGNORECASE)
MAX_KEYWORD_LENGTH = 64

# Precompute stopword sets once; building sets per line is expensive during indexing.
STANDARD_KEYWORD_SETS: Dict[str, FrozenSet[str]] = {
    str(vendor).lower(): frozenset(words)
    for vendor, words in standard_keywords.items()
}
EMPTY_KEYWORD_SET: FrozenSet[str] = frozenset()


def extract_keywords(text: str, vendor: str = 'default', preserve_stopwords: bool = False) -> List[str]:
    """
    Extracts meaningful keywords from a line of text, ignoring common stopwords.

    This function is used for both indexing configuration files and for parsing
    user search queries to find terms to look up in the cache index.

    Args:
        text: The input string (e.g., a config line or user query).
        vendor: The vendor name, used to select the correct set of stopwords.

    Returns:
        A list of lowercase keywords found in the text.
    """
    # Standardize to lowercase for consistent processing
    text_lower = text.lower()

    # Remove non-alphanumeric chars that are not part of a word (like standalone punctuation)
    # This keeps things like "word-with-hyphen" but cleans up ",.;"
    # P3 Optimization: Use precompiled regex pattern
    cleaned_text = WORD_CLEANUP_PATTERN.sub(" ", text_lower)

    vendor_key = str(vendor).lower()
    vendor_stopwords = EMPTY_KEYWORD_SET if preserve_stopwords else STANDARD_KEYWORD_SETS.get(vendor_key, EMPTY_KEYWORD_SET)
    keywords: Set[str] = set()

    # Find potential keywords. This regex is simplified for clarity, but you can use your original.
    # The key is to iterate through words.
    for word in cleaned_text.split():
        if len(word) < 3:
            continue
        if len(word) > MAX_KEYWORD_LENGTH:
            continue

        # Skip if it's a known stopword for the given vendor
        if word in vendor_stopwords:
            continue

        # Skip high-entropy or numeric noise tokens that bloat the keyword index.
        if word.isdigit() or NOISE_TOKEN_RE.match(word):
            continue

        keywords.add(word)

    return list(keywords)


def extract_literal_ips(text: str) -> List[str]:
    """
    Extract literal IP addresses from a text snippet.

    Args:
        text: Arbitrary user-provided text (regex, keywords, etc.)

    Returns:
        A list of string representations for each IP address found.
    """
    matches: List[str] = []
    for match in ip_regexp.finditer(text):
        candidate = match.group()
        try:
            # Validate and normalise; ipaddress handles both IPv4 and IPv6.
            ip_obj = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        matches.append(str(ip_obj))

    return matches
