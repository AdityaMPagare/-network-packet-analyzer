"""Packet filtering helpers.

Two layers of filtering are used:

1. A Berkeley Packet Filter (BPF) string is handed to Scapy so the
   operating system only delivers matching packets. This keeps capture
   efficient. BPF strings here are built only from validated, whitelisted
   values (see ``build_bpf_filter``), never from raw user input.
2. A pure-Python check (``matches_filters``) is applied to every parsed
   packet, so filtering also works on systems without libpcap/BPF support
   (for example when reading offline PCAP files).

All user input is validated before use; invalid values raise
``ValueError`` with a friendly message.
"""

from __future__ import annotations

import ipaddress
import re

from packet_analyzer.parser import PacketInfo

VALID_PROTOCOLS = frozenset(
    {"TCP", "UDP", "ICMP", "ICMPV6", "ARP", "DNS", "IPV4", "IPV6"}
)

_BPF_PROTOCOL_MAP = {
    "TCP": "tcp",
    "UDP": "udp",
    "ICMP": "icmp",
    "ICMPV6": "icmp6",
    "ARP": "arp",
    "DNS": "port 53",
    "IPV4": "ip",
    "IPV6": "ip6",
}

_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,253}[a-zA-Z0-9])?$")


def normalize_protocol(value: str) -> str:
    """Return the upper-case protocol name, or raise ``ValueError``."""
    protocol = (value or "").strip().upper()
    if protocol not in VALID_PROTOCOLS:
        allowed = ", ".join(sorted(VALID_PROTOCOLS))
        raise ValueError(
            f"Invalid protocol filter '{value}'. Supported protocols: {allowed}"
        )
    return protocol


def validate_port(value: str | int) -> int:
    """Return the port as an integer, or raise ``ValueError``."""
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"Invalid port '{value}'. Use a number between 1 and 65535."
        ) from None
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port '{value}'. Use a number between 1 and 65535.")
    return port


def validate_host(value: str) -> str:
    """Return the host (IP address or hostname), or raise ``ValueError``."""
    host = (value or "").strip()
    if not host:
        raise ValueError("Invalid host filter. Provide an IP address or hostname.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME_RE.match(host):
            raise ValueError(
                f"Invalid host filter '{value}'. Provide an IP address or hostname."
            ) from None
    return host


def build_bpf_filter(
    protocol: str | None = None, host: str | None = None, port: str | int | None = None
) -> str | None:
    """Build a BPF filter string from validated CLI filter options.

    Returns ``None`` when no filter options were supplied, meaning all
    traffic should be captured.
    """
    parts = []
    if protocol is not None:
        parts.append(_BPF_PROTOCOL_MAP[normalize_protocol(protocol)])
    if host is not None:
        parts.append(f"host {validate_host(host)}")
    if port is not None:
        parts.append(f"port {validate_port(port)}")
    return " and ".join(parts) if parts else None


def matches_filters(
    info: PacketInfo,
    protocol: str | None = None,
    host: str | None = None,
    port: str | int | None = None,
) -> bool:
    """Check a parsed packet against the active filter options (pure Python)."""
    if protocol is not None and info.protocol.upper() != normalize_protocol(protocol):
        return False
    if host is not None:
        validated = validate_host(host)
        if info.src_ip != validated and info.dst_ip != validated:
            return False
    if port is not None:
        port_int = validate_port(port)
        if info.src_port != port_int and info.dst_port != port_int:
            return False
    return True
