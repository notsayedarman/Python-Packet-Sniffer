# src/sniffer/blacklist.py
"""
blacklist utilities for loading and matching IP patterns.

Supports patterns like:
 - 1.2.3.4
 - 10.0.*.*
 - 192.168.1.*
 - Comments with '#' and blank lines are ignored.
"""

from typing import List


def load_blacklist(path: str) -> List[str]:
    rules = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                rules.append(line)
    except FileNotFoundError:
        # return empty list if config missing
        return []
    return rules


def ip_matches(pattern: str, ip: str) -> bool:
    """
    Match an IPv4 address against a pattern with '*' wildcards per octet.
    Example: '8.8.*.*' matches 8.8.1.1
    """
    # quick equality
    if "*" not in pattern:
        return pattern == ip

    p_parts = pattern.split(".")
    i_parts = ip.split(".")
    if len(p_parts) != 4 or len(i_parts) != 4:
        return False

    for p, i in zip(p_parts, i_parts):
        if p == "*":
            continue
        if p != i:
            return False
    return True


def is_blacklisted(ip: str, rules: List[str]) -> bool:
    return any(ip_matches(p, ip) for p in rules)
