"""Unit tests for the CLI entry point (main.py).

Live capture is simulated with ``unittest.mock`` so no network traffic,
interfaces, or privileges are required.
"""

from unittest.mock import patch

import pytest

import main
from packet_analyzer.parser import PacketInfo


def make_info(protocol="TCP"):
    return PacketInfo(timestamp="2026-01-01 00:00:00", length=74, protocol=protocol)


def test_build_parser_accepts_all_options():
    args = main.build_parser().parse_args(
        [
            "-i", "eth0",
            "-c", "10",
            "-p", "TCP",
            "--host", "192.168.1.10",
            "--port", "443",
            "-o", "out.json",
            "--pcap", "cap.pcap",
        ]
    )
    assert args.interface == "eth0"
    assert args.count == 10
    assert args.protocol == "TCP"
    assert args.host == "192.168.1.10"
    assert args.port == "443"
    assert args.output == "out.json"
    assert args.pcap == "cap.pcap"
    assert args.offline is None
    assert args.debug is False


def test_version_flag_exits_cleanly():
    with pytest.raises(SystemExit) as excinfo:
        main.build_parser().parse_args(["--version"])
    assert excinfo.value.code == 0


def test_main_rejects_invalid_count(capsys):
    assert main.main(["--count", "0"]) == 1
    assert "Invalid packet count" in capsys.readouterr().out


def test_main_rejects_invalid_protocol(capsys):
    assert main.main(["--protocol", "SMB"]) == 1
    assert "Invalid protocol" in capsys.readouterr().out


def test_main_rejects_invalid_port(capsys):
    assert main.main(["--port", "70000"]) == 1
    assert "Invalid port" in capsys.readouterr().out


def test_main_rejects_missing_offline_file(capsys):
    assert main.main(["--offline", "/nonexistent/file.pcap"]) == 1
    assert "not found" in capsys.readouterr().out.lower()


def test_main_graceful_keyboard_interrupt(capsys):
    with patch.object(main, "capture_packets", side_effect=KeyboardInterrupt):
        assert main.main(["--count", "5"]) == 0
    assert "stopped by user" in capsys.readouterr().out


def test_main_empty_capture_prints_summary(capsys):
    with patch.object(main, "capture_packets", return_value=([], [])):
        assert main.main(["--count", "5"]) == 0
    out = capsys.readouterr().out
    assert "No packets captured" in out
    assert "Total Packets: 0" in out


def test_main_captures_and_exports(capsys, tmp_path):
    parsed = [make_info(), make_info(protocol="UDP")]
    output = tmp_path / "out.json"
    with patch.object(main, "capture_packets", return_value=(parsed, [])):
        assert main.main(["--count", "2", "--output", str(output)]) == 0
    out = capsys.readouterr().out
    assert "Exported 2 packets" in out
    assert output.exists()
