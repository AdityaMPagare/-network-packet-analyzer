"""Export captured packet data to JSON, CSV, or PCAP files.

The JSON/CSV format is chosen from the output file extension: ``.json``
produces structured JSON, ``.csv`` produces a flat CSV table. PCAP export
saves the original raw Scapy packets and is handled separately from the
JSON/CSV exports.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import wrpcap

from packet_analyzer.parser import PacketInfo

CSV_COLUMNS = [
    "timestamp",
    "protocol",
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "flags",
    "length",
]


def export_to_file(path: str | Path, packets: list[PacketInfo]) -> Path:
    """Export parsed packets to ``path``, choosing the format by extension."""
    output = Path(path)
    suffix = output.suffix.lower()
    if suffix == ".json":
        export_json(output, packets)
    elif suffix == ".csv":
        export_csv(output, packets)
    else:
        raise ValueError(
            f"Unsupported output format '{suffix or output.name}'. "
            "Use a .json or .csv file."
        )
    return output


def export_json(path: Path, packets: list[PacketInfo]) -> None:
    """Write structured packet information as JSON."""
    with path.open("w", encoding="utf-8") as handle:
        json.dump([packet.to_dict() for packet in packets], handle, indent=2)


def export_csv(path: Path, packets: list[PacketInfo]) -> None:
    """Write packet information as a flat CSV table."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for packet in packets:
            data = packet.to_dict()
            writer.writerow([data[column] for column in CSV_COLUMNS])


def export_pcap(path: str | Path, packets: list[Packet]) -> Path:
    """Write the original raw Scapy packets to a PCAP file."""
    output = Path(path)
    wrpcap(str(output), packets)
    return output
