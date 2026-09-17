"""Capture statistics for the Network Packet Analyzer.

Aggregates packet counts, byte counts, protocol distribution, and top
talkers (source IPs, destination IPs, ports) using ``collections.Counter``.
"""

from __future__ import annotations

from collections import Counter

from packet_analyzer.parser import PacketInfo


class CaptureStatistics:
    """Aggregate statistics over the packets seen during a capture."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: Counter[str] = Counter()
        self.src_ips: Counter[str] = Counter()
        self.dst_ips: Counter[str] = Counter()
        self.ports: Counter[int] = Counter()

    def add_packet(self, info: PacketInfo) -> None:
        """Fold a single parsed packet into the statistics."""
        self.total_packets += 1
        self.total_bytes += info.length
        self.protocols[info.protocol] += 1
        if info.src_ip:
            self.src_ips[info.src_ip] += 1
        if info.dst_ip:
            self.dst_ips[info.dst_ip] += 1
        for port in (info.src_port, info.dst_port):
            if port is not None:
                self.ports[port] += 1

    def as_dict(self, top_n: int = 5) -> dict:
        """Return a JSON-friendly dictionary of the current statistics."""
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocols": dict(self.protocols.most_common()),
            "top_source_ips": dict(self.src_ips.most_common(top_n)),
            "top_destination_ips": dict(self.dst_ips.most_common(top_n)),
            "top_ports": dict(self.ports.most_common(top_n)),
        }

    def format_summary(self, top_n: int = 5) -> str:
        """Render a human-readable capture summary block."""
        lines = ["=============== CAPTURE SUMMARY ===============", ""]
        lines.append(f"Total Packets: {self.total_packets}")
        lines.append(f"Total Bytes:   {self.total_bytes}")
        if self.protocols:
            lines.extend(["", "Protocols:"])
            lines.extend(
                f"{name:<10}{count:>6}"
                for name, count in self.protocols.most_common()
            )
        if self.src_ips:
            lines.extend(["", "Top Source IPs:"])
            lines.extend(
                f"{ip:<18}{count:>6}" for ip, count in self.src_ips.most_common(top_n)
            )
        if self.dst_ips:
            lines.extend(["", "Top Destination IPs:"])
            lines.extend(
                f"{ip:<18}{count:>6}" for ip, count in self.dst_ips.most_common(top_n)
            )
        if self.ports:
            lines.extend(["", "Top Ports:"])
            lines.extend(
                f"{port:<18}{count:>6}" for port, count in self.ports.most_common(top_n)
            )
        return "\n".join(lines)
