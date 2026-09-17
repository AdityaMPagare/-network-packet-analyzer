"""Packet capture using Scapy.

Provides interface listing/validation used by the CLI and a single
``capture_packets`` function that wraps :func:`scapy.all.sniff` with:

* graceful behaviour on empty captures and user interrupts,
* a BPF pre-filter with automatic fallback to Python-side filtering,
* optional raw-packet collection for PCAP export.
"""

from __future__ import annotations

from typing import Callable

from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet

from packet_analyzer.filters import build_bpf_filter, matches_filters
from packet_analyzer.parser import PacketInfo, parse_packet


def list_interfaces() -> list[str]:
    """Return the names of the network interfaces visible to Scapy."""
    return list(dict.fromkeys(get_if_list()))


def validate_interface(interface: str) -> None:
    """Raise ``ValueError`` if ``interface`` is not a known interface."""
    available = list_interfaces()
    if interface not in available:
        names = "\n".join(f"  - {name}" for name in available) or "  (none found)"
        raise ValueError(
            f"Invalid network interface '{interface}'. Available interfaces:\n{names}"
        )


def capture_packets(
    interface: str | None = None,
    count: int | None = None,
    protocol: str | None = None,
    host: str | None = None,
    port: str | int | None = None,
    on_packet: Callable[[PacketInfo], None] | None = None,
    store_raw: bool = False,
    offline: str | None = None,
) -> tuple[list[PacketInfo], list[Packet]]:
    """Capture (or read offline) packets and return parsed summaries.

    Args:
        interface: Network interface to capture from; Scapy picks a
            suitable default when omitted.
        count: Number of packets to capture; ``None`` captures
            continuously until the user presses Ctrl+C (Scapy stops the
            sniff loop and returns the packets seen so far).
        protocol: Optional protocol filter (validated before use).
        host: Optional IP/hostname filter (validated before use).
        port: Optional port filter (validated before use).
        on_packet: Optional callback invoked with each parsed packet
            that passes the filters (used for live terminal display).
        store_raw: When True, also keep the raw Scapy packets so they
            can be written to a PCAP file afterwards.
        offline: When set, read packets from this PCAP file instead of
            capturing live traffic.

    Returns:
        A tuple ``(parsed_packets, raw_packets)``.
    """
    bpf = build_bpf_filter(protocol, host, port)
    parsed: list[PacketInfo] = []
    raw_packets: list[Packet] = []

    def handle_packet(packet: Packet) -> None:
        info = parse_packet(packet)
        if info is None:
            return
        if not matches_filters(info, protocol=protocol, host=host, port=port):
            return
        parsed.append(info)
        if store_raw:
            raw_packets.append(packet)
        if on_packet is not None:
            on_packet(info)

    options: dict = {"prn": handle_packet, "store": False}
    if interface:
        options["iface"] = interface
    if count is not None:
        options["count"] = count
    if offline:
        options["offline"] = offline
    if bpf:
        options["filter"] = bpf

    try:
        _run_sniff(options)
    except (Scapy_Exception, ImportError, OSError, PermissionError):
        if not bpf:
            raise
        # Some platforms cannot apply BPF filters (e.g. missing libpcap,
        # which Scapy signals with an ImportError). Retry without the
        # filter; Python-side filtering still applies.
        options.pop("filter", None)
        parsed.clear()
        raw_packets.clear()
        _run_sniff(options)
    return parsed, raw_packets


def _run_sniff(options: dict) -> None:
    """Run a single Scapy sniff session with the given options."""
    sniff(**options)
