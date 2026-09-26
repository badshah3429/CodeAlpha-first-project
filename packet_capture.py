#!/usr/bin/env python3
"""
Network Packet Capture and Analysis Tool
Captures and analyzes network traffic packets using Scapy.
"""

import sys
import argparse
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, ARP, DNS, conf


class PacketAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.packet_count = 0
        self.protocol_stats = {}

    def get_protocol_name(self, proto_num):
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            89: "OSPF",
        }
        return protocols.get(proto_num, f"Unknown({proto_num})")

    def format_payload(self, payload, max_len=64):
        if not payload:
            return ""
        try:
            decoded = payload.decode('utf-8', errors='replace')
            if len(decoded) > max_len:
                decoded = decoded[:max_len] + "..."
            return decoded.replace('\n', '\\n').replace('\r', '\\r')
        except:
            hex_str = payload.hex()
            if len(hex_str) > max_len * 2:
                hex_str = hex_str[:max_len * 2] + "..."
            return f"[HEX] {hex_str}"

    def analyze_packet(self, packet):
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        if Ether in packet:
            eth = packet[Ether]
            src_mac = eth.src
            dst_mac = eth.dst
            eth_type = eth.type
        else:
            src_mac = dst_mac = "N/A"
            eth_type = "N/A"

        if IP in packet:
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            proto = ip.proto
            proto_name = self.get_protocol_name(proto)
            ttl = ip.ttl
            ip_len = ip.len

            self.protocol_stats[proto_name] = self.protocol_stats.get(proto_name, 0) + 1

            print(f"\n[{self.packet_count}] {timestamp} | {proto_name} | {src_ip} -> {dst_ip} | TTL={ttl} | Len={ip_len}")

            if TCP in packet:
                tcp = packet[TCP]
                flags = []
                if tcp.flags & 0x02: flags.append("SYN")
                if tcp.flags & 0x10: flags.append("ACK")
                if tcp.flags & 0x01: flags.append("FIN")
                if tcp.flags & 0x04: flags.append("RST")
                if tcp.flags & 0x08: flags.append("PSH")
                if tcp.flags & 0x20: flags.append("URG")
                print(f"    TCP: {tcp.sport} -> {tcp.dport} | Flags: {' '.join(flags)} | Seq={tcp.seq} | Ack={tcp.ack}")

                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    print(f"    Payload: {self.format_payload(payload)}")

            elif UDP in packet:
                udp = packet[UDP]
                print(f"    UDP: {udp.sport} -> {udp.dport} | Len={udp.len}")

                if DNS in packet:
                    dns = packet[DNS]
                    if dns.qr == 0:
                        for q in dns.qd:
                            print(f"    DNS Query: {q.qname.decode()} | Type: {q.qtype}")
                    else:
                        for ans in dns.an:
                            print(f"    DNS Answer: {ans.rrname.decode()} -> {ans.rdata}")

                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    print(f"    Payload: {self.format_payload(payload)}")

            elif ICMP in packet:
                icmp = packet[ICMP]
                icmp_types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
                icmp_type = icmp_types.get(icmp.type, f"Type {icmp.type}")
                print(f"    ICMP: {icmp_type} | Code={icmp.code} | ID={icmp.id} | Seq={icmp.seq}")

            if self.verbose:
                print(f"    MAC: {src_mac} -> {dst_mac} | EtherType: 0x{eth_type:04x}")

        elif ARP in packet:
            arp = packet[ARP]
            op = "Request" if arp.op == 1 else "Reply"
            print(f"\n[{self.packet_count}] {timestamp} | ARP {op} | {arp.psrc} ({arp.hwsrc}) -> {arp.pdst} ({arp.hwdst})")
            self.protocol_stats["ARP"] = self.protocol_stats.get("ARP", 0) + 1

        else:
            print(f"\n[{self.packet_count}] {timestamp} | Other | MAC: {src_mac} -> {dst_mac} | EtherType: 0x{eth_type:04x}")

    def print_summary(self):
        print("\n" + "=" * 60)
        print("CAPTURE SUMMARY")
        print("=" * 60)
        print(f"Total packets captured: {self.packet_count}")
        print("\nProtocol distribution:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            pct = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            print(f"  {proto:12} : {count:5} ({pct:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Network Packet Capture and Analysis Tool")
    parser.add_argument("-i", "--interface", help="Network interface to capture on (default: all)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80', 'host 192.168.1.1')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose output including MAC addresses")
    parser.add_argument("-o", "--output", help="Save captured packets to PCAP file")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")

    args = parser.parse_args()

    if args.list_interfaces:
        print("Available network interfaces:")
        for iface in conf.ifaces.values():
            print(f"  {iface.name} - {iface.description}")
        return

    if args.interface:
        conf.iface = args.interface

    print("=" * 60)
    print("NETWORK PACKET CAPTURE TOOL")
    print("=" * 60)
    print(f"Interface: {conf.iface}")
    if args.filter:
        print(f"Filter: {args.filter}")
    if args.count:
        print(f"Packet limit: {args.count}")
    if args.output:
        print(f"Output file: {args.output}")
    print("Press Ctrl+C to stop capture\n")

    analyzer = PacketAnalyzer(verbose=args.verbose)

    captured_packets = []

    def process_packet(packet):
        analyzer.analyze_packet(packet)
        if args.output:
            captured_packets.append(packet)

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter,
            count=args.count if args.count > 0 else 0,
            prn=process_packet,
            store=False,
            stop_filter=lambda x: False
        )
    except KeyboardInterrupt:
        print("\n\nCapture stopped by user.")
    except PermissionError:
        print("\nError: Permission denied. Run as administrator/root.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

    if args.output and captured_packets:
        from scapy.all import wrpcap
        print(f"\nSaving {len(captured_packets)} packets to {args.output}...")
        wrpcap(args.output, captured_packets)
        print("Save complete.")

    analyzer.print_summary()


if __name__ == "__main__":
    main()