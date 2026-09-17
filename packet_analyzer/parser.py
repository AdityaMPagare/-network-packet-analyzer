"""Packet parsing for the Network Packet Analyzer.

Converts raw Scapy packets into lightweight :class:`PacketInfo` objects
containing only the fields useful for display, statistics, and export.

All field access is defensive: packets that lack a layer (for example an
ARP frame without an IP header, or raw Ethernet frames) simply leave the
corresponding fields at their defaults instead of raising an error.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

_ROUTABLE_PROTOCOLS = ("IPv4", "IPv6")


@dataclass
class PacketInfo:
    """Structured summary of a single captured packet."""

    timestamp: str = ""
    length: int = 0
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    protocol: str = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    flags: str = ""
    ttl: int | None = None
    info: str = ""

    def to_dict(self) -> dict:
        """Return the packet fields as a plain, JSON-serializable dict."""
        return asdict(self)

    @property
    def time_only(self) -> str:
        """Return only the clock-time portion of the timestamp."""
        return self.timestamp.split()[-1] if self.timestamp else ""


def parse_packet(packet: Packet | None) -> PacketInfo | None:
    """Parse a Scapy packet into a :class:`PacketInfo` summary.

    Returns ``None`` when the packet is empty or cannot be handled, so
    callers can skip unsupported packet types gracefully.
    """
    if packet is None:
        return None
    try:
        info = PacketInfo()
        _base_fields(packet, info)
        if packet.haslayer(ARP):
            _arp_fields(packet[ARP], info)
            return info
        _network_fields(packet, info)
        _transport_fields(packet, info)
        _dns_fields(packet, info)
        return info
    except Exception:
        return None


def _base_fields(packet: Packet, info: PacketInfo) -> None:
    """Fill in timestamp, length, and Ethernet MAC addresses when present."""
    info.timestamp = datetime.fromtimestamp(float(packet.time)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    info.length = len(packet)
    ether = packet.getlayer(Ether)
    if ether is not None:
        info.src_mac = str(ether.src)
        info.dst_mac = str(ether.dst)


def _arp_fields(arp: Packet, info: PacketInfo) -> None:
    """Extract fields from an ARP request or reply."""
    info.protocol = "ARP"
    info.src_ip = str(arp.psrc)
    info.dst_ip = str(arp.pdst)


def _network_fields(packet: Packet, info: PacketInfo) -> None:
    """Extract fields from the IPv4/IPv6 header when present."""
    if packet.haslayer(IP):
        ip = packet[IP]
        info.src_ip = str(ip.src)
        info.dst_ip = str(ip.dst)
        info.ttl = int(ip.ttl)
        info.protocol = "IPv4"
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        info.src_ip = str(ip6.src)
        info.dst_ip = str(ip6.dst)
        info.ttl = int(ip6.hlim)
        info.protocol = "IPv6"


def _transport_fields(packet: Packet, info: PacketInfo) -> None:
    """Extract TCP/UDP/ICMP fields when present, keeping ports from DNS."""
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info.src_port = int(tcp.sport)
        info.dst_port = int(tcp.dport)
        info.flags = str(tcp.flags)
        if info.protocol in _ROUTABLE_PROTOCOLS:
            info.protocol = "TCP"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info.src_port = int(udp.sport)
        info.dst_port = int(udp.dport)
        if info.protocol in _ROUTABLE_PROTOCOLS:
            info.protocol = "UDP"
    elif packet.haslayer(ICMP) and info.protocol == "IPv4":
        info.protocol = "ICMP"
    elif info.protocol == "IPv6" and (
        packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply)
    ):
        info.protocol = "ICMPv6"


def _dns_fields(packet: Packet, info: PacketInfo) -> None:
    """Label DNS traffic and extract the queried name when available."""
    if not packet.haslayer(DNS):
        return
    dns = packet[DNS]
    info.protocol = "DNS"
    qname = _dns_qname(dns)
    if qname:
        is_query = int(getattr(dns, "qr", 0)) == 0
        role = "Query" if is_query else "Response"
        info.info = f"{role}: {qname}"


def _dns_qname(dns: Packet) -> str:
    """Return the first DNS question name, handling Scapy version differences."""
    question = getattr(dns, "qd", None)
    if question is None:
        return ""
    if isinstance(question, (list, tuple)):
        if not question:
            return ""
        first = question[0]
    else:
        first = question
    qname = getattr(first, "qname", None)
    if not qname:
        return ""
    if isinstance(qname, bytes):
        return qname.decode(errors="replace").rstrip(".")
    return str(qname).rstrip(".")
