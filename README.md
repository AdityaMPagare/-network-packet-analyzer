# Network Packet Analyzer

[![CI](https://github.com/AdityaMPagare/-network-packet-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/AdityaMPagare/-network-packet-analyzer/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A Python-based network packet analyzer for packet capture, protocol parsing,
filtering, statistics, and export. A clean, beginner-friendly defensive
network-analysis project built as a personal cybersecurity portfolio piece.

> **Use responsibly.** This tool passively captures and analyzes traffic on
> networks you own or are explicitly authorized to analyze. See
> [Ethical / Legal Use](#ethical--legal-use-notice).

## Features

- Live packet capture from any visible network interface (Scapy)
- Continuous capture until `Ctrl+C`, or a fixed packet count
- Parses Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP (and ICMPv6 echo), and DNS
- Clean, readable terminal output with a live packet table
- Filtering by protocol, host (IP/hostname), and port (combinable)
- Capture statistics: totals, protocol distribution, top talkers, top ports
- Export to **JSON** or **CSV** (format chosen by file extension)
- Export raw packets to **PCAP** (separate from JSON/CSV export)
- Analyze an existing PCAP file offline (`--offline`) — no live capture needed
- Graceful handling of `Ctrl+C`, permission errors, and invalid input

## Technology Stack

| Component        | Technology                          |
| ---------------- | ----------------------------------- |
| Language         | Python 3.10+                        |
| Packet capture   | [Scapy](https://scapy.net)          |
| CLI              | `argparse` (standard library)       |
| Statistics       | `collections.Counter` (stdlib)      |
| Export           | `json`, `csv` (stdlib), Scapy PCAP  |
| Testing          | [pytest](https://pytest.org)        |

## Architecture

```
                 +----------------------+
                 |       main.py        |
                 |   (CLI entry point)  |
                 +----------+-----------+
                            |
              parses args, validates input
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
 +----------------+  +--------------+  +----------------+
 |  capture.py    |  |  filters.py  |  |  statistics.py |
 | (Scapy sniff + |  | (BPF string  |  | (Counter-based |
 |  Ctrl+C guard) |  |  + Python)   |  |  aggregation)  |
 +-------+--------+  +------+-------+  +--------+-------+
         |                  |                   ^
         v                  v                   |
 +----------------+   filtered packets          |
 |   parser.py    | ------------> PacketInfo ---+
 | (Scapy packet  |
 |  -> dataclass) |
 +----------------+
          |
          v
 +----------------+
 |  exporter.py   |   JSON / CSV / PCAP files
 +----------------+
```

**Data flow:** `capture.py` sniffs packets (BPF pre-filter + Python-side
filtering), `parser.py` converts each packet into a lightweight
`PacketInfo` dataclass, `statistics.py` aggregates them, and
`exporter.py` writes JSON/CSV/PCAP output at the end of the run.

## Installation

```bash
git clone https://github.com/AdityaMPagare/-network-packet-analyzer.git network-packet-analyzer
cd network-packet-analyzer
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux setup

Packet capture requires raw socket access. Run the analyzer with `sudo`:

```bash
sudo .venv/bin/python main.py --count 20
```

Alternatively, grant the Python interpreter raw-capture capabilities
(lets you run without `sudo`):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))
```

> Note: BPF capture filters need libpcap. On minimal systems the tool
> automatically falls back to Python-side filtering, so filters still work.

### Windows / WSL notes

- **Windows (native):** install [Npcap](https://npcap.com/) with
  "WinPcap API-compatible mode" enabled, then run the terminal as
  Administrator.
- **WSL2:** live capture works on the virtual `eth0` interface with root
  privileges (`sudo python main.py`). WSL1 does not support raw sockets —
  use the `--offline` mode there instead.

## Usage Examples

Capture 20 packets on the default interface:

```bash
sudo python main.py --count 20
```

Capture continuously on a specific interface until `Ctrl+C`:

```bash
sudo python main.py --interface eth0
```

Filter TCP traffic on port 443:

```bash
sudo python main.py --protocol TCP --port 443
```

Filter traffic to/from a host:

```bash
sudo python main.py --host 192.168.1.10
```

Capture 100 packets and export parsed data plus raw PCAP:

```bash
sudo python main.py --count 100 --output packets.json --pcap capture.pcap
sudo python main.py --count 100 --output packets.csv
```

Analyze an existing PCAP file (no capture privileges needed):

```bash
python main.py --offline capture.pcap
```

## CLI Options

```text
usage: main.py [-h] [--version] [-i INTERFACE] [-c COUNT] [-p PROTOCOL]
               [--host HOST] [--port PORT] [-o FILE] [--pcap FILE]
               [--offline FILE] [--debug]

Network Packet Analyzer - capture, parse, and export network packets
(defensive network analysis).

options:
  -h, --help            show this help message and exit
  --version             show the program version and exit
  -i, --interface INTERFACE
                        network interface to capture from (default: Scapy
                        picks a suitable one)
  -c, --count COUNT     number of packets to capture (default: capture until
                        Ctrl+C)
  -p, --protocol PROTOCOL
                        only capture this protocol (ARP, DNS, ICMP, ICMPV6,
                        IPV4, IPV6, TCP, UDP)
  --host HOST           only capture packets to/from this IP address or hostname
  --port PORT           only capture packets to/from this port
  -o, --output FILE     export parsed packets to FILE (.json or .csv; format chosen by file extension)
  --pcap FILE           save the raw captured packets to a PCAP file (separate from --output)
  --offline FILE        analyze an existing PCAP file instead of capturing live traffic
  --debug               show full Python tracebacks for troubleshooting
```

## Example Output

```text
========================================
        NETWORK PACKET ANALYZER
========================================

[INFO] Capturing on default interface (press Ctrl+C to stop)

TIME      PROTOCOL  SOURCE               DESTINATION         LENGTH
22:01:04  TCP       192.168.1.10:53122   142.250.195.14:443  74
22:01:04  UDP       192.168.1.10:5353    224.0.0.251:5353    98
22:01:05  ICMP      192.168.1.10         8.8.8.8             98
22:01:05  DNS       192.168.1.10:53000   8.8.8.8:53          87 Query: example.com

=============== CAPTURE SUMMARY ===============

Total Packets: 4
Total Bytes:     357

Protocols:
TCP            1
UDP            1
ICMP           1
DNS            1

Top Source IPs:
192.168.1.10            4

Top Destination IPs:
8.8.8.8                 2
142.250.195.14          1

Top Ports:
443                     2
5353                    1
```

## Testing

The test suite uses synthetic packets built with Scapy's constructors — no
real network traffic is required:

```bash
pytest
```

With verbose output:

```bash
pytest -v
```

Tests also run automatically via GitHub Actions on every push and pull
request (see `.github/workflows/ci.yml`).

## Project Structure

```
network-packet-analyzer/
├── main.py                  # CLI entry point (argparse, display, error handling)
├── requirements.txt         # Dependencies (scapy, pytest)
├── README.md
├── LICENSE                  # MIT
├── .gitignore               # Excludes captures, caches, virtualenvs
├── .github/
│   └── workflows/
│       └── ci.yml           # GitHub Actions test workflow
├── packet_analyzer/
│   ├── __init__.py
│   ├── capture.py           # Scapy sniffing, interface validation, Ctrl+C guard
│   ├── parser.py            # Packet -> PacketInfo dataclass
│   ├── filters.py           # Input validation, BPF builder, Python-side matching
│   ├── statistics.py        # Counter-based capture statistics
│   └── exporter.py          # JSON / CSV / PCAP export
└── tests/
    ├── __init__.py
    ├── test_parser.py       # IPv4/TCP/UDP/ICMP/ARP/IPv6/DNS parsing
    ├── test_statistics.py   # Statistics aggregation and summary
    ├── test_filters.py      # Validation, BPF building, matching
    ├── test_exporter.py     # JSON/CSV/PCAP export
    └── test_main.py         # CLI behavior (mocked capture)
```

## Limitations

- Live packet capture generally requires appropriate privileges
  (`sudo` on Linux, Administrator on Windows, Npcap installed).
- BPF capture filters require libpcap; without it the tool falls back to
  Python-side filtering (still correct, slightly less efficient).
- This is a terminal tool: no GUI, no packet reassembly, no deep
  protocol dissectors beyond the layers listed above.
- Non-IP, non-Ethernet frames (and unrecognized payloads) are reported
  as `OTHER` with best-effort fields.
- On WSL1, raw sockets are unavailable — use `--offline` mode.

## Ethical / Legal Use Notice

This tool is intended **only** for:

- Your own machine
- Networks you own
- Networks where you have explicit authorization to perform packet analysis
- Cybersecurity education and defensive network troubleshooting

Packet captures can contain sensitive information (usernames, browsing
activity, unencrypted traffic). Never capture traffic on networks you do
not have permission to analyze, and never share or commit raw PCAP files.
The authors are not responsible for misuse of this software.

## Future Improvements

- Conversation/flow tracking (group packets into TCP/UDP streams)
- Additional dissectors (HTTP headers, TLS handshake metadata, DHCP)
- Live-updating statistics view
- Async/daemon mode with configurable capture rotation
- Optional alarm rules (e.g., flag unusual port scans)
