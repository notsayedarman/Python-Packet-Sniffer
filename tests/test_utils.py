# tests/test_utils.py
from src.sniffer.utils import anonymize_ip, reverse_dns, PTR_CACHE

def test_anonymize_ip():
    assert anonymize_ip("192.168.1.42", keep_octets=3) == "192.168.1.*"
    assert anonymize_ip("192.168.1.42", keep_octets=2) == "192.168.*.*"
    assert anonymize_ip("192.168.1.42", keep_octets=0) == "*.*.*.*"
    assert anonymize_ip("invalid-ip", keep_octets=3) == "invalid-ip"

def test_reverse_dns_disabled():
    # when disabled, should return empty list and not populate cache
    PTR_CACHE.clear()
    res = reverse_dns("8.8.8.8", enable_ptr=False)
    assert res == []
    assert "8.8.8.8" not in PTR_CACHE