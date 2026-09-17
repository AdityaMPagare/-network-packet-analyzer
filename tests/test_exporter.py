"""Unit tests for JSON/CSV/PCAP export."""

import csv
import json

import pytest
from scapy.all import Ether, IP, TCP, rdpcap

from packet_analyzer.exporter import CSV_COLUMNS, export_pcap, export_to_file
from packet_analyzer.parser import PacketInfo


def make_info():
    return PacketInfo(
        timestamp="2026-01-01 12:30:00",
        length=74,
        src_mac="aa:bb:cc:dd:ee:01",
        dst_mac="aa:bb:cc:dd:ee:02",
        src_ip="192.168.1.10",
        dst_ip="142.250.195.14",
        protocol="TCP",
        src_port=52341,
        dst_port=443,
        flags="SA",
        ttl=64,
    )


def test_export_json(tmp_path):
    path = tmp_path / "packets.json"
    export_to_file(path, [make_info()])
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["protocol"] == "TCP"
    assert data[0]["src_ip"] == "192.168.1.10"
    assert data[0]["src_port"] == 52341
    assert data[0]["length"] == 74


def test_export_csv(tmp_path):
    path = tmp_path / "packets.csv"
    export_to_file(path, [make_info()])
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows[0] == CSV_COLUMNS
    assert rows[1][0] == "2026-01-01 12:30:00"
    assert rows[1][1] == "TCP"
    assert rows[1][4] == "192.168.1.10"
    assert rows[1][7] == "443"


def test_export_unsupported_extension(tmp_path):
    with pytest.raises(ValueError):
        export_to_file(tmp_path / "packets.txt", [make_info()])


def test_export_empty_list(tmp_path):
    path = tmp_path / "empty.json"
    export_to_file(path, [])
    assert json.loads(path.read_text(encoding="utf-8")) == []
    csv_path = tmp_path / "empty.csv"
    export_to_file(csv_path, [])
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    assert rows == [CSV_COLUMNS]


def test_export_pcap(tmp_path):
    path = tmp_path / "capture.pcap"
    pkt = (
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / TCP(sport=1000, dport=80)
    )
    export_pcap(path, [pkt])
    assert len(rdpcap(str(path))) == 1
