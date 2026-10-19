"""
Naive keyword-blacklist filter (the 'old way' of stopping SQL injection).

It simply looks for known-bad substrings. It is included to be COMPARED against
the grammar-based detector: it misses obfuscated attacks (extra spaces, different
tautologies, comments used as whitespace) and it also blocks harmless input
that happens to contain a banned character such as ';'.
"""

BLACKLIST = [
    "or 1=1",
    "or '1'='1'",
    "' or '",
    "--",
    "union select",
    "drop table",
    ";",
]


def blacklist_scan(query, blacklist=BLACKLIST):
    """Return (blocked, matched_patterns). Plain case-insensitive substring match."""
    lowered = query.lower()
    matched = [p for p in blacklist if p in lowered]
    return bool(matched), matched
