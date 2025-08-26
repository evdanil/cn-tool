import re
from typing import List

# You might need to import these from your keywords.py file
# from ..keywords import standard_keywords

# Assuming keywords.py is at the root level for now
# If you move it, adjust the import path.
from wordlists.keywords import standard_keywords


def extract_keywords(text: str, vendor: str = 'default') -> List[str]:
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
    keywords: List[str] = []

    # Standardize to lowercase for consistent processing
    text_lower = text.lower()

    # Remove non-alphanumeric chars that are not part of a word (like standalone punctuation)
    # This keeps things like "word-with-hyphen" but cleans up ",.;"
    cleaned_text = re.sub(r"[\W_]+", " ", text_lower)

    # Use a set for efficient stopword checking
    vendor_stopwords = set(standard_keywords.get(vendor, ()))

    # Find potential keywords. This regex is simplified for clarity, but you can use your original.
    # The key is to iterate through words.
    for word in cleaned_text.split():
        if len(word) < 3:
            continue

        # Skip if it's a known stopword for the given vendor
        if word in vendor_stopwords:
            continue

        # Skip purely numeric words that are likely not useful (e.g., '100', '443')
        # Your original regex handled this well. This is an alternative way.
        if word.isdigit() and len(word) < 4:
            continue

        keywords.append(word)

    return list(set(keywords))  # Return unique keywords
