from __future__ import annotations

import argparse
import json
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Literal

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.text import Text
from scapy.all import AsyncSniffer, ICMP, IP, TCP, UDP, Packet

PROTOCOL_CHOICES = ("tcp", "udp", "icmp")


@dataclass
class PacketRecord:
    time: str
    proto: str
    source: str
    destination: str
    flags: str
    size: int


class SnifferState:
    def __init__(self, max_rows: int) -> None:
        self._recent: deque[PacketRecord] = deque(maxlen=max_rows)
        self._all_records: list[PacketRecord] = []
        self._stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0}
        self._lock = Lock()

    def add(self, record: PacketRecord) -> None:
        with self._lock:
            self._recent.append(record)
            self._all_records.append(record)
            self._stats["Total"] += 1
            if record.proto in ("TCP", "UDP", "ICMP"):
                self._stats[record.proto] += 1

    def snapshot(self) -> tuple[list[PacketRecord], dict[str, int]]:
        with self._lock:
            return list(self._recent), dict(self._stats)

    def all_records(self) -> list[PacketRecord]:
        with self._lock:
            return list(self._all_records)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Live packet sniffer for local network (Windows + Scapy + Rich)."
    )
    parser.add_argument(
        "-i", "--iface", type=str, default=None, help="Network interface."
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=100,
        help="Number of packets to capture (0 means unlimited).",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        type=str,
        default=None,
        help="Raw BPF filter passed to Scapy.",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        choices=PROTOCOL_CHOICES,
        default=None,
        help="Protocol filter: tcp, udp, or icmp.",
    )
    parser.add_argument("--port", type=int, default=None, help="Port filter.")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=20,
        help="Number of latest packets visible in live table.",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to output log file. If omitted, auto-generated.",
    )
    parser.add_argument(
        "--log-format",
        type=str,
        choices=("txt", "json"),
        default="txt",
        help="Output log format.",
    )
    args = parser.parse_args()

    if args.count < 0:
        raise SystemExit("count must be >= 0")
    if args.max_rows <= 0:
        raise SystemExit("max-rows must be > 0")
    if args.port is not None and not (1 <= args.port <= 65535):
        raise SystemExit("port must be in range 1..65535")
    if args.protocol == "icmp" and args.port is not None:
        raise SystemExit("--port is not supported with --protocol icmp")

    return args


def build_capture_filter(args: argparse.Namespace) -> str | None:
    clauses: list[str] = []

    if args.bpf_filter:
        clauses.append(f"({args.bpf_filter})")

    if args.protocol in ("tcp", "udp"):
        if args.port is None:
            clauses.append(f"({args.protocol})")
        else:
            clauses.append(f"({args.protocol} port {args.port})")
    elif args.protocol == "icmp":
        clauses.append("(icmp)")
    elif args.port is not None:
        clauses.append(f"(tcp port {args.port} or udp port {args.port})")

    if not clauses:
        return None
    return " and ".join(clauses)


def ip_proto_name(proto_number: int) -> str:
    if proto_number == 6:
        return "TCP"
    if proto_number == 17:
        return "UDP"
    if proto_number == 1:
        return "ICMP"
    return "OTHER"


def format_endpoint(ip: str, port: int | None) -> str:
    if ip == "-":
        return "-"
    if port is None:
        return ip
    return f"{ip}:{port}"


def packet_to_record(packet: Packet) -> PacketRecord:
    timestamp = datetime.now().strftime("%H:%M:%S")
    packet_time = getattr(packet, "time", None)
    if packet_time is not None:
        try:
            timestamp = datetime.fromtimestamp(float(packet_time)).strftime("%H:%M:%S")
        except (TypeError, ValueError, OSError):
            pass

    src_ip = "-"
    dst_ip = "-"
    proto = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    flags = "-"

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(getattr(ip_layer, "src", "-"))
        dst_ip = str(getattr(ip_layer, "dst", "-"))
        proto = ip_proto_name(int(getattr(ip_layer, "proto", 0)))

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        proto = "TCP"
        src_port = int(getattr(tcp_layer, "sport", 0))
        dst_port = int(getattr(tcp_layer, "dport", 0))
        flags = str(getattr(tcp_layer, "flags", "-"))
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        proto = "UDP"
        src_port = int(getattr(udp_layer, "sport", 0))
        dst_port = int(getattr(udp_layer, "dport", 0))
    elif packet.haslayer(ICMP):
        proto = "ICMP"

    size = len(packet)

    return PacketRecord(
        time=timestamp,
        proto=proto,
        source=format_endpoint(src_ip, src_port),
        destination=format_endpoint(dst_ip, dst_port),
        flags=flags,
        size=size,
    )


def render_dashboard(rows: list[PacketRecord], stats: dict[str, int]) -> Group:
    table = Table(title="Live Packet Sniffer", show_lines=False)
    table.add_column("Time", justify="center")
    table.add_column("Proto", justify="center")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Flags", justify="center")
    table.add_column("Size", justify="right")

    for row in rows:
        table.add_row(
            row.time,
            row.proto,
            row.source,
            row.destination,
            row.flags,
            str(row.size),
        )

    stats_line = (
        f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | "
        f"ICMP: {stats['ICMP']} | Total: {stats['Total']}"
    )

    return Group(table, Text(stats_line))


def default_log_path(log_format: Literal["txt", "json"]) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"sniffer_log_{stamp}.{log_format}")


def resolve_log_path(log_file: str | None, log_format: Literal["txt", "json"]) -> Path:
    if not log_file:
        return default_log_path(log_format)

    path = Path(log_file)
    if path.suffix.lower() not in (".txt", ".json"):
        path = path.with_suffix(f".{log_format}")
    return path


def save_txt(path: Path, records: list[PacketRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in records:
            handle.write(
                f"{row.time} | {row.proto:<5} | {row.source} -> {row.destination} | "
                f"Flags: {row.flags} | Size: {row.size}\n"
            )


def save_json(path: Path, records: list[PacketRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(
            [asdict(row) for row in records], handle, ensure_ascii=False, indent=2
        )


def save_records(
    path: Path, log_format: Literal["txt", "json"], records: list[PacketRecord]
) -> None:
    if log_format == "json":
        save_json(path, records)
    else:
        save_txt(path, records)


def main() -> None:
    args = parse_args()
    capture_filter = build_capture_filter(args)
    capture_count = args.count

    state = SnifferState(max_rows=args.max_rows)
    console = Console()

    def on_packet(packet: Packet) -> None:
        try:
            state.add(packet_to_record(packet))
        except Exception:
            return

    sniffer = AsyncSniffer(
        prn=on_packet,
        store=False,
        count=capture_count,
        iface=args.iface,
        filter=capture_filter,
    )

    console.print("Starting live sniffer...")
    console.print(f"Interface: {args.iface or 'default'}")
    console.print(
        f"Packet limit: {'unlimited' if capture_count == 0 else capture_count}"
    )
    console.print(f"BPF filter: {capture_filter or '(none)'}")
    console.print("Run terminal as Administrator on Windows.")

    interrupted = False

    with Live(
        render_dashboard([], {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0}),
        refresh_per_second=4,
        console=console,
    ) as live:
        sniffer.start()
        try:
            while True:
                rows, stats = state.snapshot()
                live.update(render_dashboard(rows, stats), refresh=True)

                if (
                    capture_count > 0
                    and stats["Total"] >= capture_count
                    and not sniffer.running
                ):
                    break
                if capture_count == 0 and not sniffer.running:
                    break

                time.sleep(0.5)
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if sniffer.running:
                try:
                    sniffer.stop()
                except Exception:
                    pass

            rows, stats = state.snapshot()
            live.update(render_dashboard(rows, stats), refresh=True)

    records = state.all_records()
    output_path = resolve_log_path(args.log_file, args.log_format)
    save_records(output_path, args.log_format, records)

    if interrupted:
        console.print("Capture interrupted by user (Ctrl+C).")

    console.print("Capture finished.")
    console.print(
        f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']} | Total: {stats['Total']}"
    )
    console.print(f"Log saved to: {output_path}")


if __name__ == "__main__":
    main()
