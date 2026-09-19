#!/usr/bin/env python3
"""Network Packet Analyzer - command-line entry point.

Captures packets from a network interface, parses common protocols,
prints live packet information, shows capture statistics, and exports
results to JSON/CSV/PCAP.

Intended for authorized, defensive use on networks you own or are
explicitly permitted to analyze. See README.md for details.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from packet_analyzer import __version__
    from packet_analyzer.capture import capture_packets, validate_interface
    from packet_analyzer.exporter import export_pcap, export_to_file
    from packet_analyzer.filters import VALID_PROTOCOLS
    from packet_analyzer.parser import PacketInfo
    from packet_analyzer.statistics import CaptureStatistics
    from scapy.error import Scapy_Exception
except ImportError as exc:
    print(f"[ERROR] Missing dependency: {exc.name or exc}")
    print("Install the requirements with: pip install -r requirements.txt")
    sys.exit(1)

BANNER = (
    "========================================\n"
    "        NETWORK PACKET ANALYZER\n"
    "========================================\n"
)

TABLE_HEADER = (
    f"{'TIME':<9}{'PROTOCOL':<10}{'SOURCE':<20}{'DESTINATION':<20}{'LENGTH':<6}"
)


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Network Packet Analyzer - capture, parse, and export "
        "network packets (defensive network analysis).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="show the program version and exit",
    )
    parser.add_argument(
        "-i",
        "--interface",
        metavar="INTERFACE",
        help="network interface to capture from "
        "(default: Scapy picks a suitable one)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        metavar="COUNT",
        help="number of packets to capture (default: capture until Ctrl+C)",
    )
    parser.add_argument(
        "-p",
        "--protocol",
        metavar="PROTOCOL",
        help=f"only capture this protocol ({', '.join(sorted(VALID_PROTOCOLS))})",
    )
    parser.add_argument(
        "--host",
        metavar="HOST",
        help="only capture packets to/from this IP address or hostname",
    )
    parser.add_argument(
        "--port",
        metavar="PORT",
        help="only capture packets to/from this port",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="export parsed packets to FILE (.json or .csv; "
        "format chosen by file extension)",
    )
    parser.add_argument(
        "--pcap",
        metavar="FILE",
        help="save the raw captured packets to a PCAP file "
        "(separate from --output)",
    )
    parser.add_argument(
        "--offline",
        metavar="FILE",
        help="analyze an existing PCAP file instead of capturing live traffic",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show full Python tracebacks for troubleshooting",
    )
    return parser


def print_packet(info: PacketInfo) -> None:
    """Print one packet as a single readable table row."""
    src = f"{info.src_ip}:{info.src_port}" if info.src_port is not None else info.src_ip
    dst = f"{info.dst_ip}:{info.dst_port}" if info.dst_port is not None else info.dst_ip
    line = (
        f"{info.time_only:<9}{info.protocol:<10}{src:<20}{dst:<20}{info.length:<6}"
    )
    if info.info:
        line += f" {info.info}"
    print(line)


def main(argv: list[str] | None = None) -> int:
    """Run the analyzer; returns a process exit code."""
    args = build_parser().parse_args(argv)

    try:
        if args.count is not None and args.count <= 0:
            raise ValueError("Invalid packet count. Use a positive integer.")

        if args.offline and not Path(args.offline).exists():
            raise ValueError(f"PCAP file not found: {args.offline}")

        if args.interface and not args.offline:
            validate_interface(args.interface)

        print(BANNER)
        if args.offline:
            print(f"[INFO] Reading packets from {args.offline}\n")
        else:
            target = args.interface or "default interface"
            print(f"[INFO] Capturing on {target} (press Ctrl+C to stop)\n")
        print(TABLE_HEADER)

        stats = CaptureStatistics()

        def on_packet(info: PacketInfo) -> None:
            stats.add_packet(info)
            print_packet(info)

        parsed, raw_packets = capture_packets(
            interface=args.interface,
            count=args.count,
            protocol=args.protocol,
            host=args.host,
            port=args.port,
            on_packet=on_packet,
            store_raw=bool(args.pcap),
            offline=args.offline,
        )

        if stats.total_packets == 0:
            print(
                "\n[INFO] No packets captured. "
                "Try a different interface or relax the filters."
            )

        print(f"\n{stats.format_summary()}")

        if args.output:
            output_path = export_to_file(args.output, parsed)
            print(f"\n[INFO] Exported {len(parsed)} packets to {output_path}")

        if args.pcap:
            if raw_packets:
                pcap_path = export_pcap(args.pcap, raw_packets)
                print(f"[INFO] Saved {len(raw_packets)} raw packets to {pcap_path}")
            else:
                print(f"[WARNING] No raw packets to save to {args.pcap}")
        return 0

    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.")
        return 0
    except ValueError as exc:
        print(f"\n[ERROR] {exc}")
        return 1
    except PermissionError:
        print("\n[ERROR] Permission denied.")
        print(
            "Try running the analyzer with appropriate packet-capture "
            "privileges (for example with sudo)."
        )
        return 1
    except (OSError, Scapy_Exception) as exc:
        print(f"\n[ERROR] Capture failed: {exc}")
        return 1
    except Exception as exc:
        if args.debug:
            raise
        print(f"\n[ERROR] Unexpected error: {exc}")
        print("Run again with --debug to see the full traceback.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
