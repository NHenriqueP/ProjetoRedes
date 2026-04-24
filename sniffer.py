#!/usr/bin/env python3
import argparse
import csv
import json
import signal
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

from scapy.all import ARP, DHCP, DNS, ICMP, IP, IPv6, TCP, UDP, Ether, Raw, sniff  # type: ignore


@dataclass
class PacketRecord:
    timestamp: str
    interface: str
    protocol: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    size: int
    summary: str


class CaptureStats:
    def __init__(self) -> None:
        self.started_at = datetime.now()
        self.ended_at: Optional[datetime] = None

        self.total_packets = 0
        self.total_bytes = 0
        self.max_size = 0

        self.transport_counts: Counter[str] = Counter()
        self.application_counts: Counter[str] = Counter()

        self.src_packets: Counter[str] = Counter()
        self.src_bytes: Counter[str] = Counter()
        self.dst_packets: Counter[str] = Counter()
        self.dst_bytes: Counter[str] = Counter()

        self.conversation_packets: Counter[Tuple[str, str]] = Counter()
        self.conversation_bytes: Counter[Tuple[str, str]] = Counter()

        self.size_buckets: Counter[str] = Counter()

        self.ipv4_total = 0
        self.ipv4_fragmented = 0

        self.icmp_total = 0
        self.icmp_errors = 0

        self.tcp_retransmissions = 0
        self._tcp_seen_segments: Dict[Tuple[str, str, int, int, int, int], int] = defaultdict(int)

        self.pps_by_second: Counter[str] = Counter()

    @staticmethod
    def _pct(part: int, total: int) -> float:
        return (part / total * 100.0) if total > 0 else 0.0

    @staticmethod
    def _format_mib(num_bytes: int) -> str:
        mib = num_bytes / (1024 * 1024)
        return f"{mib:.2f} MiB"

    @staticmethod
    def _format_pair(pair: Tuple[str, str]) -> str:
        return f"{pair[0]} <-> {pair[1]}"

    def _classify_application(self, pkt, record: PacketRecord) -> str:
        if pkt.haslayer(DNS):
            return "DNS"

        if pkt.haslayer(TCP):
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            if sport in {80, 443, 8080, 8443} or dport in {80, 443, 8080, 8443}:
                return "WEB"
            if sport == 53 or dport == 53:
                return "DNS"

        if pkt.haslayer(UDP):
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            if sport in {80, 443, 8080, 8443} or dport in {80, 443, 8080, 8443}:
                return "WEB"
            if sport == 53 or dport == 53:
                return "DNS"

        if record.protocol in {"TCP", "UDP", "ICMP"}:
            return "OUTROS"

        return "OUTROS"

    def update(self, pkt, record: PacketRecord) -> None:
        now = datetime.now()
        second_key = now.strftime("%Y-%m-%d %H:%M:%S")
        self.pps_by_second[second_key] += 1

        self.total_packets += 1
        self.total_bytes += record.size
        self.max_size = max(self.max_size, record.size)

        if record.protocol in {"TCP", "UDP", "ICMP"}:
            self.transport_counts[record.protocol] += 1

        self.application_counts[self._classify_application(pkt, record)] += 1

        if record.src_ip != "-":
            self.src_packets[record.src_ip] += 1
            self.src_bytes[record.src_ip] += record.size

        if record.dst_ip != "-":
            self.dst_packets[record.dst_ip] += 1
            self.dst_bytes[record.dst_ip] += record.size

        if record.src_ip != "-" and record.dst_ip != "-":
            pair = tuple(sorted((record.src_ip, record.dst_ip)))
            self.conversation_packets[pair] += 1
            self.conversation_bytes[pair] += record.size

        if record.size <= 128:
            self.size_buckets["pequenos_<=128B"] += 1
        elif record.size >= 1400:
            self.size_buckets["perto_MTU_>=1400B"] += 1
        else:
            self.size_buckets["medios"] += 1

        if pkt.haslayer(IP):
            self.ipv4_total += 1
            ip = pkt[IP]
            flags = int(ip.flags)
            frag_offset = int(ip.frag)
            if (flags & 0x1) != 0 or frag_offset > 0:
                self.ipv4_fragmented += 1

        if pkt.haslayer(ICMP):
            self.icmp_total += 1
            icmp_type = int(pkt[ICMP].type)
            if icmp_type in {3, 4, 5, 11, 12}:
                self.icmp_errors += 1

        if pkt.haslayer(TCP) and record.src_ip != "-" and record.dst_ip != "-":
            tcp = pkt[TCP]
            payload_len = len(bytes(tcp.payload))
            if payload_len > 0:
                key = (
                    record.src_ip,
                    record.dst_ip,
                    int(tcp.sport),
                    int(tcp.dport),
                    int(tcp.seq),
                    payload_len,
                )
                if self._tcp_seen_segments[key] > 0:
                    self.tcp_retransmissions += 1
                self._tcp_seen_segments[key] += 1

    def finish(self) -> None:
        self.ended_at = datetime.now()

    def render_report(self) -> str:
        end_time = self.ended_at or datetime.now()
        duration = max((end_time - self.started_at).total_seconds(), 0.0001)

        transport_total = (
            self.transport_counts.get("TCP", 0)
            + self.transport_counts.get("UDP", 0)
            + self.transport_counts.get("ICMP", 0)
        )

        avg_size = (self.total_bytes / self.total_packets) if self.total_packets > 0 else 0.0
        peak_pps = max(self.pps_by_second.values(), default=0)

        top_src_by_bytes = self.src_bytes.most_common(5)
        top_dst_by_bytes = self.dst_bytes.most_common(5)
        top_conversations = self.conversation_bytes.most_common(5)

        lines = [
            "\n=== RELATORIO DE CAPTURA ===",
            f"Duracao: {duration:.2f} s",
            f"Pacotes analisados: {self.total_packets}",
            f"Volume total: {self._format_mib(self.total_bytes)}",
            f"Pico PPS: {peak_pps}",
            "",
            "1) Distribuicao de Protocolos",
            (
                "  Transporte: "
                f"TCP={self._pct(self.transport_counts.get('TCP', 0), transport_total):.2f}% "
                f"UDP={self._pct(self.transport_counts.get('UDP', 0), transport_total):.2f}% "
                f"ICMP={self._pct(self.transport_counts.get('ICMP', 0), transport_total):.2f}%"
            ),
            (
                "  Aplicacao: "
                f"WEB={self._pct(self.application_counts.get('WEB', 0), self.total_packets):.2f}% "
                f"DNS={self._pct(self.application_counts.get('DNS', 0), self.total_packets):.2f}% "
                f"OUTROS={self._pct(self.application_counts.get('OUTROS', 0), self.total_packets):.2f}%"
            ),
            "",
            "2) Top Talkers",
            "  Top 5 IPs de origem (por bytes):",
        ]

        if top_src_by_bytes:
            for ip, total in top_src_by_bytes:
                lines.append(
                    f"    - {ip}: {self._format_mib(total)} ({self.src_packets[ip]} pacotes)"
                )
        else:
            lines.append("    - sem dados IPv4/IPv6")

        lines.append("  Top 5 IPs de destino (por bytes):")
        if top_dst_by_bytes:
            for ip, total in top_dst_by_bytes:
                lines.append(
                    f"    - {ip}: {self._format_mib(total)} ({self.dst_packets[ip]} pacotes)"
                )
        else:
            lines.append("    - sem dados IPv4/IPv6")

        lines.append("  Top 5 conversas (pares de IP por bytes):")
        if top_conversations:
            for pair, total in top_conversations:
                lines.append(
                    f"    - {self._format_pair(pair)}: {self._format_mib(total)} ({self.conversation_packets[pair]} pacotes)"
                )
        else:
            lines.append("    - sem conversas IP")

        lines.extend(
            [
                "",
                "3) Analise de Tamanho",
                f"  Tamanho medio: {avg_size:.2f} B",
                f"  Tamanho maximo: {self.max_size} B",
                (
                    "  Distribuicao: "
                    f"<=128B={self._pct(self.size_buckets.get('pequenos_<=128B', 0), self.total_packets):.2f}% "
                    f">=1400B={self._pct(self.size_buckets.get('perto_MTU_>=1400B', 0), self.total_packets):.2f}% "
                    f"intermedios={self._pct(self.size_buckets.get('medios', 0), self.total_packets):.2f}%"
                ),
                (
                    "  Taxa de fragmentacao IPv4: "
                    f"{self._pct(self.ipv4_fragmented, self.ipv4_total):.2f}% "
                    f"({self.ipv4_fragmented}/{self.ipv4_total})"
                ),
                "",
                "4) Caca aos Erros",
                (
                    "  Taxa de erros ICMP: "
                    f"{self._pct(self.icmp_errors, self.icmp_total):.2f}% "
                    f"({self.icmp_errors}/{self.icmp_total})"
                ),
                f"  Retransmissoes TCP (estimativa): {self.tcp_retransmissions}",
                "",
                "5) Desempenho e Volume",
                f"  Volume total capturado: {self._format_mib(self.total_bytes)}",
                f"  Pico de pacotes por segundo: {peak_pps}",
            ]
        )

        return "\n".join(lines)


class LoggerManager:
    def __init__(self, txt_path: Optional[str], csv_path: Optional[str], json_path: Optional[str]):
        self.txt_path = txt_path
        self.csv_path = csv_path
        self.json_path = json_path

        self._txt_file = None
        self._csv_file = None
        self._csv_writer = None
        self._json_file = None
        self._is_first_json = True

        if self.txt_path:
            self._txt_file = open(self.txt_path, "w", encoding="utf-8")

        if self.csv_path:
            self._csv_file = open(self.csv_path, "w", newline="", encoding="utf-8")
            self._csv_writer = csv.DictWriter(
                self._csv_file,
                fieldnames=[
                    "timestamp",
                    "interface",
                    "protocol",
                    "src_mac",
                    "dst_mac",
                    "src_ip",
                    "dst_ip",
                    "size",
                    "summary",
                ],
            )
            self._csv_writer.writeheader()

        if self.json_path:
            self._json_file = open(self.json_path, "w", encoding="utf-8")
            self._json_file.write("[\n")

    def write(self, record: PacketRecord) -> None:
        row = asdict(record)

        if self._txt_file is not None:
            self._txt_file.write(
                (
                    f"[{record.timestamp}] iface={record.interface} "
                    f"proto={record.protocol} "
                    f"mac={record.src_mac}->{record.dst_mac} "
                    f"ip={record.src_ip}->{record.dst_ip} "
                    f"len={record.size} "
                    f"summary={record.summary}\n"
                )
            )
            self._txt_file.flush()

        if self._csv_writer is not None:
            self._csv_writer.writerow(row)
            assert self._csv_file is not None
            self._csv_file.flush()

        if self._json_file is not None:
            if not self._is_first_json:
                self._json_file.write(",\n")
            self._json_file.write(json.dumps(row, ensure_ascii=False))
            self._json_file.flush()
            self._is_first_json = False

    def close(self) -> None:
        if self._json_file is not None:
            self._json_file.write("\n]\n")
            self._json_file.close()

        if self._csv_file is not None:
            self._csv_file.close()

        if self._txt_file is not None:
            self._txt_file.close()


class PacketSniffer:
    def __init__(
        self,
        interface: str,
        protocol_filter: Optional[str],
        ip_filter: Optional[str],
        mac_filter: Optional[str],
        logger: LoggerManager,
        live: bool,
        live_conversations: bool,
        bpf_filter: Optional[str] = None,
    ):
        self.interface = interface
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.ip_filter = ip_filter
        self.mac_filter = mac_filter.lower() if mac_filter else None
        self.logger = logger
        self.live = live
        self.live_conversations = live_conversations
        self.bpf_filter = bpf_filter
        self._running = True
        self.stats = CaptureStats()
        self._conversation_events_seen: Set[Tuple[str, str, str]] = set()

    def _get_protocol(self, pkt) -> str:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(DHCP):
            return "DHCP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(IPv6):
            return "IPv6"
        if pkt.haslayer(IP):
            return "IPv4"
        return "OTHER"

    def _get_summary(self, pkt, protocol: str) -> str:
        if protocol == "ARP":
            op = pkt[ARP].op
            return "ARP request" if op == 1 else "ARP reply" if op == 2 else "ARP"

        if protocol == "ICMP":
            icmp_type = pkt[ICMP].type
            if icmp_type == 8:
                return "ICMP echo request"
            if icmp_type == 0:
                return "ICMP echo reply"
            return f"ICMP type={icmp_type}"

        if protocol == "DHCP":
            options = pkt[DHCP].options
            msg_map = {
                1: "DHCP Discover",
                2: "DHCP Offer",
                3: "DHCP Request",
                5: "DHCP ACK",
            }
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    return msg_map.get(opt[1], f"DHCP type={opt[1]}")
            return "DHCP"

        if protocol == "TCP":
            flags = pkt[TCP].flags
            return f"TCP flags={flags}"

        if protocol == "UDP":
            return f"UDP sport={pkt[UDP].sport} dport={pkt[UDP].dport}"

        if pkt.haslayer(Raw):
            return "Raw payload"

        return pkt.summary()

    def _build_record(self, pkt) -> PacketRecord:
        protocol = self._get_protocol(pkt)

        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "-"
        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "-"

        src_ip = "-"
        dst_ip = "-"
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        return PacketRecord(
            timestamp=datetime.now().isoformat(timespec="seconds"),
            interface=self.interface,
            protocol=protocol,
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip,
            dst_ip=dst_ip,
            size=len(pkt),
            summary=self._get_summary(pkt, protocol),
        )

    def _accept(self, record: PacketRecord) -> bool:
        if self.protocol_filter and record.protocol != self.protocol_filter:
            return False

        if self.ip_filter and self.ip_filter not in (record.src_ip, record.dst_ip):
            return False

        if self.mac_filter and self.mac_filter not in (record.src_mac.lower(), record.dst_mac.lower()):
            return False

        return True

    def _handle_packet(self, pkt) -> None:
        record = self._build_record(pkt)
        if not self._accept(record):
            return

        self.stats.update(pkt, record)

        if self.live:
            if self.live_conversations:
                src = record.src_ip if record.src_ip != "-" else record.src_mac
                dst = record.dst_ip if record.dst_ip != "-" else record.dst_mac
                a, b = sorted((src, dst))

                if record.protocol == "ICMP" and record.summary in {"ICMP echo request", "ICMP echo reply"}:
                    event_name = "PING"
                else:
                    event_name = record.protocol

                event_key = (event_name, a, b)
                if event_key not in self._conversation_events_seen:
                    print(f"[{record.timestamp}] {record.interface:<8} {event_name:<6} entre {a} <-> {b}")
                    self._conversation_events_seen.add(event_key)
            else:
                print(
                    (
                        f"[{record.timestamp}] {record.interface:<8} "
                        f"{record.protocol:<6} {record.src_ip:>20} -> {record.dst_ip:<20} "
                        f"len={record.size:<5} {record.summary}"
                    )
                )

        self.logger.write(record)

    def stop(self, *_args) -> None:
        self._running = False

    def run(self) -> None:
        print(f"Capturing on interface '{self.interface}'... Press Ctrl+C to stop.")
        sniff(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            filter=self.bpf_filter,
            stop_filter=lambda _pkt: not self._running,
        )
        self.stats.finish()
        print(self.stats.render_report())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple packet sniffer for RC TP2")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("--protocol", help="Protocol filter: ARP, IPv4, IPv6, ICMP, TCP, UDP, DHCP, DNS")
    parser.add_argument("--ip", help="IP filter (source or destination)")
    parser.add_argument("--mac", help="MAC filter (source or destination)")
    parser.add_argument("--bpf", help="BPF expression filter (optional)")
    parser.add_argument("--no-live", action="store_true", help="Disable live output")
    parser.add_argument(
        "--live-conversations",
        action="store_true",
        help="Show one bidirectional live event per conversation/protocol instead of per-packet direction",
    )
    parser.add_argument("--log-txt", help="Path to TXT log file")
    parser.add_argument("--log-csv", help="Path to CSV log file")
    parser.add_argument("--log-json", help="Path to JSON log file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logger = LoggerManager(args.log_txt, args.log_csv, args.log_json)

    sniffer = PacketSniffer(
        interface=args.interface,
        protocol_filter=args.protocol,
        ip_filter=args.ip,
        mac_filter=args.mac,
        logger=logger,
        live=not args.no_live,
        live_conversations=args.live_conversations,
        bpf_filter=args.bpf,
    )

    signal.signal(signal.SIGINT, sniffer.stop)

    try:
        sniffer.run()
    except PermissionError:
        print("Permission denied. Run with sudo/root privileges.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Capture error: {exc}", file=sys.stderr)
        return 1
    finally:
        logger.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
