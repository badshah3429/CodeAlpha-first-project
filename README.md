# Network Packet Capture Tool

A Python program for capturing and analyzing network traffic packets using Scapy.

## Installation

```bash
pip install -r requirements.txt
```

**Note:** On Windows, you may need to install Npcap (https://npcap.com/) for packet capture to work. On Linux, run with sudo.

## Usage

```bash
# Capture all packets on default interface
python packet_capture.py

# Capture on specific interface
python packet_capture.py -i "Ethernet 0"

# Capture with BPF filter (e.g., only HTTP traffic)
python packet_capture.py -f "tcp port 80"

# Capture specific number of packets
python packet_capture.py -c 100

# Verbose output (shows MAC addresses)
python packet_capture.py -v

# Save to PCAP file for later analysis
python packet_capture.py -o capture.pcap

# List available interfaces
python packet_capture.py --list-interfaces
```

## Features

- **Protocol Analysis**: Identifies TCP, UDP, ICMP, ARP, DNS protocols
- **Packet Details**: Shows source/destination IPs, ports, flags, sequence numbers
- **Payload Display**: Shows packet payloads in readable format (text or hex)
- **DNS Analysis**: Displays DNS queries and responses
- **Statistics**: Provides protocol distribution summary
- **PCAP Export**: Save captures for Wireshark analysis

## Example Output

```
[1] 14:32:15.123 | TCP | 192.168.1.100 -> 93.184.216.34 | TTL=64 | Len=60
    TCP: 54321 -> 80 | Flags: SYN | Seq=123456789 | Ack=0

[2] 14:32:15.145 | TCP | 93.184.216.34 -> 192.168.1.100 | TTL=52 | Len=60
    TCP: 80 -> 54321 | Flags: SYN ACK | Seq=987654321 | Ack=123456790

[3] 14:32:15.146 | TCP | 192.168.1.100 -> 93.184.216.34 | TTL=64 | Len=52
    TCP: 54321 -> 80 | Flags: ACK | Seq=123456790 | Ack=987654322
    Payload: GET / HTTP/1.1
    Host: example.com
    ...
```

## Common BPF Filters

| Filter | Description |
|--------|-------------|
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS traffic |
| `host 192.168.1.1` | Traffic to/from specific IP |
| `net 192.168.1.0/24` | Traffic in subnet |
| `icmp` | Ping/ICMP traffic |
| `arp` | ARP traffic |

## Requirements

- Python 3.7+
- Scapy 2.5+
- Npcap (Windows) or libpcap (Linux/macOS)
- Administrator/root privileges