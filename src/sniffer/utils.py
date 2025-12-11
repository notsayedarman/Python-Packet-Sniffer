# src/sniffer/utils.py
"""
Utility functions:
 - logging setup
 - anonymize IP (optional)
 - cached reverse DNS lookups with TTL (toggleable)
"""

from typing import Dict, List
import time
import logging
import ipaddress
import requests

# default PTR endpoint (public)
DEFAULT_GOOGLE_PTR = "https://dns.google/resolve?name={}&type=PTR"

# PTR cache structure: ip -> (timestamp, list_of_ptrs)
PTR_CACHE: Dict[str, tuple] = {}

# default TTL for PTR cache (seconds)
PTR_TTL = 300  # 5 minutes


def setup_logging(level: int = logging.INFO) -> None:
    fmt = "%(asctime)s %(levelname)s: %(message)s"
    logging.basicConfig(format=fmt, level=level)


def anonymize_ip(ip: str, keep_octets: int = 3) -> str:
    """
    Mask trailing octets for privacy. keep_octets must be 0..3.
    Example: anonymize_ip('192.168.1.42', keep_octets=3) -> '192.168.1.*'
    """
    try:
        parts = ip.split(".")
        if len(parts) != 4 or not (0 <= keep_octets <= 3):
            return ip
        masked = parts[:keep_octets] + ["*"] * (4 - keep_octets)
        return ".".join(masked)
    except Exception:
        return ip


def reverse_dns(ip: str, enable_ptr: bool = True, endpoint: str = DEFAULT_GOOGLE_PTR) -> List[str]:
    """
    Do reverse DNS PTR lookup with simple caching and TTL.
    Returns list of PTR names (may be empty).
    If enable_ptr is False returns [] immediately.
    """
    if not enable_ptr:
        return []

    # check cache
    now = time.time()
    cached = PTR_CACHE.get(ip)
    if cached:
        ts, value = cached
        if now - ts < PTR_TTL:
            return value

    try:
        ptr = ipaddress.ip_address(ip).reverse_pointer
    except Exception:
        PTR_CACHE[ip] = (now, [])
        return []

    try:
        r = requests.get(endpoint.format(ptr), timeout=3)
        j = r.json()
        ans = j.get("Answer", [])
        ptrs = [x["data"].rstrip(".") for x in ans if x.get("type") == 12]
        PTR_CACHE[ip] = (now, ptrs)
        return ptrs
    except Exception:
        PTR_CACHE[ip] = (now, [])
        return []
