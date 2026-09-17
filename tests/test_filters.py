"""Unit tests for filter validation, BPF building, and matching."""

import pytest

from packet_analyzer.filters import (
    build_bpf_filter,
    matches_filters,
    normalize_protocol,
    validate_host,
    validate_port,
)
from packet_analyzer.parser import PacketInfo


def make_info(
    protocol="TCP",
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=52341,
    dst_port=443,
):
    return PacketInfo(
        timestamp="2026-01-01 00:00:00",
        length=74,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_normalize_protocol_accepts_known_protocols():
    assert normalize_protocol("tcp") == "TCP"
    assert normalize_protocol(" Arp ") == "ARP"
    assert normalize_protocol("DNS") == "DNS"


def test_normalize_protocol_rejects_unknown():
    with pytest.raises(ValueError):
        normalize_protocol("SMB")
    with pytest.raises(ValueError):
        normalize_protocol("")
    with pytest.raises(ValueError):
        normalize_protocol(None)


def test_validate_port_accepts_valid_ports():
    assert validate_port("443") == 443
    assert validate_port(80) == 80
    assert validate_port(1) == 1
    assert validate_port(65535) == 65535


def test_validate_port_rejects_invalid():
    for value in ("0", "65536", "abc", "-1", "", None):
        with pytest.raises(ValueError):
            validate_port(value)


def test_validate_host_accepts_ips_and_hostnames():
    assert validate_host("192.168.1.10") == "192.168.1.10"
    assert validate_host("example.com") == "example.com"


def test_validate_host_rejects_invalid():
    for value in ("not a host!", "", "   ", "bad host;ls"):
        with pytest.raises(ValueError):
            validate_host(value)


def test_build_bpf_filter_combinations():
    assert build_bpf_filter() is None
    assert build_bpf_filter(protocol="TCP") == "tcp"
    assert build_bpf_filter(protocol="DNS") == "port 53"
    assert build_bpf_filter(protocol="UDP", port=53) == "udp and port 53"
    assert (
        build_bpf_filter(host="192.168.1.10", port="443")
        == "host 192.168.1.10 and port 443"
    )


def test_build_bpf_filter_rejects_bad_input():
    with pytest.raises(ValueError):
        build_bpf_filter(protocol="NOPE")
    with pytest.raises(ValueError):
        build_bpf_filter(port="99999999")
    with pytest.raises(ValueError):
        build_bpf_filter(host="bad host!")


def test_matches_filters_protocol():
    info = make_info()
    assert matches_filters(info, protocol="TCP")
    assert not matches_filters(info, protocol="UDP")


def test_matches_filters_host_and_port():
    info = make_info()
    assert matches_filters(info, host="192.168.1.10")
    assert matches_filters(info, host="8.8.8.8")
    assert not matches_filters(info, host="10.0.0.1")
    assert matches_filters(info, port=443)
    assert matches_filters(info, port=52341)
    assert not matches_filters(info, port=80)


def test_matches_filters_combined():
    info = make_info()
    assert matches_filters(info, protocol="TCP", port=443)
    assert not matches_filters(info, protocol="TCP", port=80)
    assert not matches_filters(info, protocol="UDP", port=443)


def test_matches_filters_no_filter_matches_everything():
    assert matches_filters(make_info())
