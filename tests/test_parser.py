"""Unit tests for packet parsing using synthetic Scapy packets.

No real network traffic is required: packets are built with Scapy's
packet constructors and parsed with ``parse_packet``.
"""

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    Ether,
    ICMP,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
)

from packet_analyzer.parser import parse_packet


def make_tcp_packet():
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="192.168.1.10", dst="142.250.195.14", ttl=64)
        / TCP(sport=52341, dport=443, flags="SA")
    )


def test_ipv4_tcp_packet_parsing():
    info = parse_packet(make_tcp_packet())
    assert info is not None
    assert info.protocol == "TCP"
    assert info.src_mac == "aa:bb:cc:dd:ee:01"
    assert info.dst_mac == "aa:bb:cc:dd:ee:02"
    assert info.src_ip == "192.168.1.10"
    assert info.dst_ip == "142.250.195.14"
    assert info.src_port == 52341
    assert info.dst_port == 443
    assert info.flags == "SA"
    assert info.ttl == 64
    assert info.length > 0
    assert info.timestamp


def test_udp_packet_parsing():
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=32)
        / UDP(sport=5353, dport=53)
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "UDP"
    assert info.src_port == 5353
    assert info.dst_port == 53
    assert info.ttl == 32
    assert info.flags == ""


def test_icmp_packet_parsing():
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8)
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "ICMP"
    assert info.src_ip == "192.168.1.10"
    assert info.dst_ip == "8.8.8.8"
    assert info.src_port is None
    assert info.dst_port is None


def test_arp_packet_parsing():
    pkt = Ether() / ARP(op=1, psrc="192.168.1.5", pdst="192.168.1.1")
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "ARP"
    assert info.src_ip == "192.168.1.5"
    assert info.dst_ip == "192.168.1.1"
    assert info.ttl is None
    assert info.src_port is None


def test_ipv6_tcp_packet_parsing():
    pkt = (
        Ether()
        / IPv6(src="fe80::1", dst="2001:db8::1", hlim=51)
        / TCP(sport=1000, dport=80)
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "TCP"
    assert info.src_ip == "fe80::1"
    assert info.dst_ip == "2001:db8::1"
    assert info.ttl == 51


def test_dns_packet_parsing():
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "DNS"
    assert info.src_port == 53000
    assert info.dst_port == 53
    assert "example.com" in info.info


def test_unsupported_packet_is_labeled_other():
    pkt = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02") / Raw(
        load=b"\x00\x01\x02"
    )
    info = parse_packet(pkt)
    assert info is not None
    assert info.protocol == "OTHER"
    assert info.src_mac == "aa:bb:cc:00:00:01"
    assert info.src_ip == ""


def test_none_packet_returns_none():
    assert parse_packet(None) is None
