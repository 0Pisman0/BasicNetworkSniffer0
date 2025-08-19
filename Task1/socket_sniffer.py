#!/usr/bin/env python3

# Minimal, Linux-only raw socket IPv4 sniffer (for learning purposes).
# Requires root. Does not apply BPF filters or decode higher layers fully.
import argparse, os, socket, struct, sys, time
from datetime import datetime

ETH_P_ALL = 0x0003  # receive all protocols

def parse_ipv4_header(data):
    # Ethernet (14 bytes) + IPv4 header
    if len(data) < 34:  # 14 eth + 20 ip
        return None
    eth_header = data[:14]
    ip_header = data[14:34]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    total_length = iph[2]
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return {
        "version": version,
        "ihl": ihl,
        "length": total_length,
        "protocol": protocol,
        "src": src_ip,
        "dst": dst_ip
    }

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha — Minimal Raw Socket Sniffer (Linux/IPv4)")
    parser.add_argument("-i","--iface", required=True, help="Interface to sniff on (e.g., eth0)")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[-] Requires root. Try: sudo -E python3 socket_sniffer.py -i eth0", file=sys.stderr)
        sys.exit(1)

    # Open raw socket bound to interface
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((args.iface, 0))

    print(f"[+] Listening on {args.iface}. Press Ctrl+C to stop.")
    try:
        while True:
            packet, addr = s.recvfrom(65535)
            hdr = parse_ipv4_header(packet)
            if not hdr:
                continue
            ts = datetime.now().strftime("%H:%M:%S")
            proto = {1:"ICMP",6:"TCP",17:"UDP"}.get(hdr["protocol"], str(hdr["protocol"]))
            print(f"{ts}  IPv{hdr['version']}  {proto:<4}  {hdr['src']:<18} -> {hdr['dst']:<18} len={hdr['length']}")
    except KeyboardInterrupt:
        print("\n[+] Stopping...")
    finally:
        s.close()

if __name__ == "__main__":
    main()
