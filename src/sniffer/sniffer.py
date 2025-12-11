#!/usr/bin/env python3
# src/sniffer/sniffer.py
"""
Main packet sniffer CLI.

Features:
 - Loads blacklist from config/blacklist.txt
 - Optional reverse-DNS PTR lookups (toggleable)
 - Optional IP anonymization for logs
 - Simple flow deduplication to avoid spamming logs
 - Uses Python logging (configurable level)
"""

import argparse
import logging
import time
from collections import defaultdict

from scapy.all import sniff, IP, TCP, UDP  # scapy import
from .blacklist import load_blacklist, is_blacklisted
from .utils import setup_logging, reverse_dns, anonymize_ip

# flow deduplication window in seconds
FLOW_WINDOW = 1.0


class FlowDeduper:
    """
    Tracks last-seen (src,dst) pairs with timestamps and ignores repeated flows
    within the sliding window.
    """
    def __init__(self, window: float = FLOW_WINDOW):
        self.window = window
        self.last_seen = {}

    def should_ignore(self, src: str, dst: str) -> bool:
        key = (src, dst)
        now = time.time()
        last = self.last_seen.get(key)
        if last and (now - last) < self.window:
            return True
        self.last_seen[key] = now
        # also clean old entries occasionally
        if len(self.last_seen) > 5000:
            cutoff = now - (self.window * 10)
            for k, v in list(self.last_seen.items()):
                if v < cutoff:
                    del self.last_seen[k]
        return False


def format_flow_log(ts: str, src: str, sport, dst: str, dport, proto: str) -> str:
    return f"[{ts}] {src}:{sport} → {dst}:{dport} ({proto})"


def handle_packet(pkt, rules, opts, deduper):
    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # skip blacklisted addresses
    if is_blacklisted(src, rules) or is_blacklisted(dst, rules):
        logging.debug("packet skipped due to blacklist")
        return

    # dedupe flows
    if deduper.should_ignore(src, dst):
        logging.debug("duplicate flow ignored")
        return

    proto = "OTHER"
    sport = dport = ""
    if pkt.haslayer(TCP):
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    ts = time.strftime("%H:%M:%S")

    display_src = anonymize_ip(src, keep_octets=opts.anonymize_keep) if opts.anonymize else src
    display_dst = anonymize_ip(dst, keep_octets=opts.anonymize_keep) if opts.anonymize else dst

    logging.info(format_flow_log(ts, display_src, sport, display_dst, dport, proto))

    # PTR lookups (if enabled)
    psrc = reverse_dns(src, enable_ptr=opts.ptr)
    pdst = reverse_dns(dst, enable_ptr=opts.ptr)

    if psrc:
        logging.info("  PTR-src: %s", ", ".join(psrc))
    if pdst:
        logging.info("  PTR-dst: %s", ", ".join(pdst))

    logging.debug("-" * 60)


def main():
    parser = argparse.ArgumentParser(prog="sniffer", description="Lightweight packet sniffer with blacklist and PTR support")
    parser.add_argument("-i", "--iface", help="Network interface to capture on (requires privileges)", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter string for scapy (default: ip)", default="ip")
    parser.add_argument("-c", "--config", help="Path to blacklist file", default="config/blacklist.txt")
    parser.add_argument("--ptr", help="Enable reverse-DNS PTR lookups", action="store_true")
    parser.add_argument("--anonymize", help="Mask trailing octets in IPs for privacy", action="store_true")
    parser.add_argument("--anonymize-keep", help="Number of leading octets to keep when anonymizing (0..3)", type=int, default=3)
    parser.add_argument("-v", "--verbose", help="Verbose (DEBUG) logging", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level)

    rules = load_blacklist(args.config)
    logging.debug("Loaded blacklist rules: %s", rules)

    # combine options into a simple namespace-like object
    class O: pass
    opts = O()
    opts.ptr = args.ptr
    opts.anonymize = args.anonymize
    opts.anonymize_keep = max(0, min(3, args.anonymize_keep))

    deduper = FlowDeduper()

    logging.info("Starting sniffer (ptr=%s, anonymize=%s)", opts.ptr, opts.anonymize)
    try:
        sniff(filter=args.filter, prn=lambda p: handle_packet(p, rules, opts, deduper), store=False, iface=args.iface)
    except PermissionError:
        logging.error("Permission denied. Run with sudo or Administrator privileges to capture on interfaces.")
    except Exception as e:
        logging.exception("Unexpected error in sniffer: %s", e)


if __name__ == "__main__":
    main()
