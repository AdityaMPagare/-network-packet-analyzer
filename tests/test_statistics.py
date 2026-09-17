"""Unit tests for capture statistics."""

from packet_analyzer.parser import PacketInfo
from packet_analyzer.statistics import CaptureStatistics


def make_info(
    protocol="TCP",
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=5000,
    dst_port=443,
    length=100,
):
    return PacketInfo(
        timestamp="2026-01-01 00:00:00",
        length=length,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_counts_packets_and_bytes():
    stats = CaptureStatistics()
    stats.add_packet(make_info())
    stats.add_packet(make_info(length=50))
    assert stats.total_packets == 2
    assert stats.total_bytes == 150


def test_protocol_distribution():
    stats = CaptureStatistics()
    stats.add_packet(make_info(protocol="TCP"))
    stats.add_packet(make_info(protocol="TCP"))
    stats.add_packet(make_info(protocol="UDP"))
    stats.add_packet(make_info(protocol="ARP"))
    assert stats.protocols["TCP"] == 2
    assert stats.protocols["UDP"] == 1
    assert stats.protocols["ARP"] == 1


def test_top_ips_and_ports():
    stats = CaptureStatistics()
    stats.add_packet(make_info(src_ip="192.168.1.10", dst_ip="8.8.8.8", dst_port=443))
    stats.add_packet(make_info(src_ip="192.168.1.10", dst_ip="8.8.8.8", dst_port=443))
    stats.add_packet(make_info(src_ip="192.168.1.20", dst_ip="1.1.1.1", dst_port=80))
    assert stats.src_ips.most_common(1)[0] == ("192.168.1.10", 2)
    assert stats.src_ips["192.168.1.20"] == 1
    assert stats.dst_ips["8.8.8.8"] == 2
    assert stats.dst_ips["1.1.1.1"] == 1
    assert stats.ports[443] == 2
    assert stats.ports[80] == 1
    assert stats.ports[5000] == 3


def test_empty_values_are_not_counted():
    stats = CaptureStatistics()
    stats.add_packet(PacketInfo(timestamp="t", length=10, protocol="OTHER"))
    assert stats.total_packets == 1
    assert not stats.src_ips
    assert not stats.dst_ips
    assert not stats.ports


def test_empty_statistics():
    stats = CaptureStatistics()
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert "Total Packets: 0" in stats.format_summary()


def test_format_summary_contents():
    stats = CaptureStatistics()
    stats.add_packet(make_info(protocol="TCP"))
    stats.add_packet(make_info(protocol="UDP"))
    summary = stats.format_summary()
    assert "CAPTURE SUMMARY" in summary
    assert "Total Bytes:" in summary
    assert "TCP" in summary
    assert "UDP" in summary
    assert "Top Source IPs" in summary
    assert "192.168.1.10" in summary


def test_as_dict_is_json_friendly():
    import json

    stats = CaptureStatistics()
    stats.add_packet(make_info())
    data = json.loads(json.dumps(stats.as_dict()))
    assert data["total_packets"] == 1
    assert data["protocols"] == {"TCP": 1}
