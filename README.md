# PacketSniffX  
A lightweight, privacy-friendly, modular packet-sniffer built with Python and Scapy.

PacketSniffX focuses on **clean output**, **safe defaults**, and **extendable architecture**.  
It includes a **wildcard blacklist**, **optional IP anonymization**, **optional reverse-DNS lookups**,  
and **flow deduplication** to prevent log spam.

This project is ideal for:
- Learning packet sniffing  
- Debugging local network traffic  
- Building advanced network-monitoring tools  
- Safe, privacy-aware packet inspection  

---

## Features

### ✓ Clean & Modular Structure  
Separated into clear components:
- `sniffer.py` — packet capture & CLI  
- `blacklist.py` — wildcard-based filtering  
- `utils.py` — logging, PTR caching, anonymization  

### ✓ Blacklist Support  
Supports wildcard patterns per octet:
```

192.168.*.*
10.0.*.*
8.8.8.8

```

### ✓ Flow Deduplication  
Prevents logs from repeating the same connection every millisecond.

### ✓ Optional PTR Lookups  
Reverse-DNS lookups with TTL caching.  
Disable to improve performance or privacy.

### ✓ IP Anonymization  
Masks trailing octets:
```

192.168.1.42 → 192.168.1.*

```

### ✓ Logging System  
Uses Python `logging` with clean output.

---

## Folder Structure

```

project-root/
├── src/
│   └── sniffer/
│       ├── **init**.py
│       ├── sniffer.py
│       ├── blacklist.py
│       └── utils.py
├── config/
│   └── blacklist.txt
├── tests/
│   ├── test_blacklist.py
│   └── test_utils.py
├── docs/
│   └── overview.md
├── requirements.txt
└── README.md

```

---

## Installation

### 1. Create Virtual Environment
```bash
python -m venv .venv
```

### 2. Activate It

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```bash
.\.venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic Sniffing

```bash
python -m src.sniffer.sniffer -i eth0
```

### Enable PTR Lookups

```bash
python -m src.sniffer.sniffer -i eth0 --ptr
```

### Anonymize IP Addresses

```bash
python -m src.sniffer.sniffer -i eth0 --anonymize
```

### Control Anonymization Level

```bash
python -m src.sniffer.sniffer -i eth0 --anonymize --anonymize-keep 2
```

### Verbose Debug Mode

```bash
python -m src.sniffer.sniffer -i eth0 -v
```

### Custom Blacklist File

```bash
python -m src.sniffer.sniffer -c config/blacklist.txt
```

---

## Example Output

```
[14:32:10] 192.168.1.*:443 → 142.250.182.*:443 (TCP)
  PTR-dst: bom12s16-in-f14.1e100.net
```

---

## Blacklist Format

`config/blacklist.txt` supports:

| Pattern       | Meaning              |
| ------------- | -------------------- |
| `8.8.8.8`     | Exact IP             |
| `8.8.*.*`     | Entire subnet        |
| `192.168.*.*` | Private LAN range    |
| `# comment`   | Ignored comment line |

Example:

```text
# Block Google DNS
8.8.8.8
8.8.4.4

# Block private LAN
192.168.*.*
```

---

## Testing

```bash
pytest -q
```

---

## Troubleshooting

### Permission Denied

Run as root/admin:

Linux:

```bash
sudo python -m src.sniffer.sniffer -i eth0
```

Windows:
Run PowerShell/terminal as Administrator.

### PTR Lookups Slow

Disable PTR:

```bash
--ptr false
```

---

## Extending the Project

Ideas:

* JSON log output
* Save logs to file
* Live dashboard
* Local DNS resolver integration
* GeoIP mapping

I can generate extensions if needed.

---

## Contributing

PRs and issues welcome. Improvements most helpful in:

* Performance optimizations
* Protocol decoders
* JSON/file exporters
* Local resolver support

---

## License

MIT License.

```# Python-Packet-Sniffer
