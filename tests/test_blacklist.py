# tests/test_blacklist.py
from src.sniffer.blacklist import ip_matches, is_blacklisted

def test_ip_matches_exact():
    assert ip_matches("1.2.3.4", "1.2.3.4")
    assert not ip_matches("1.2.3.5", "1.2.3.4")

def test_ip_matches_wildcard():
    assert ip_matches("8.8.*.*", "8.8.1.1")
    assert not ip_matches("8.8.*.*", "8.7.1.1")
    assert ip_matches("*.*.*.*", "10.0.0.1")

def test_is_blacklisted():
    rules = ["10.0.*.*", "1.2.3.4"]
    assert is_blacklisted("10.0.1.5", rules)
    assert is_blacklisted("1.2.3.4", rules)
    assert not is_blacklisted("9.9.9.9", rules)
