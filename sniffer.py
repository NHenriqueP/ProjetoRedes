#!/usr/bin/env python3
import argparse
import csv
import json
import signal
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

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
        bpf_filter: Optional[str] = None,
    ):
        self.interface = interface
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.ip_filter = ip_filter
        self.mac_filter = mac_filter.lower() if mac_filter else None
        self.logger = logger
        self.live = live
        self.bpf_filter = bpf_filter
        self._running = True

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

        if self.live:
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple packet sniffer for RC TP2")
    parser.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("--protocol", help="Protocol filter: ARP, IPv4, IPv6, ICMP, TCP, UDP, DHCP, DNS")
    parser.add_argument("--ip", help="IP filter (source or destination)")
    parser.add_argument("--mac", help="MAC filter (source or destination)")
    parser.add_argument("--bpf", help="BPF expression filter (optional)")
    parser.add_argument("--no-live", action="store_true", help="Disable live output")
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
