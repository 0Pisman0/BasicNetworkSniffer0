#!/usr/bin/env python3

import argparse, csv, json, os, signal, sys, time
from datetime import datetime
from typing import Optional, Dict, Any

try:
    from scapy.all import sniff, PcapWriter, conf, Ether, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    print("[-] Scapy import failed. Did you install requirements? `pip install -r requirements.txt`", file=sys.stderr)
    raise

stop_requested = False
pcap_writer = None
csv_writer = None
csv_file_handle = None
json_file_handle = None

def human_proto(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    # Could add more here (e.g., ARP, DNS)
    if pkt.haslayer("ARP"):
        return "ARP"
    return "Other"

def extract(pkt) -> Dict[str, Any]:
    eth = pkt.getlayer(Ether)
    ip4 = pkt.getlayer(IP)
    ip6 = pkt.getlayer(IPv6)
    tcp = pkt.getlayer(TCP)
    udp = pkt.getlayer(UDP)

    src = dst = None
    ip_version = None

    if ip4:
        src, dst = ip4.src, ip4.dst
        ip_version = 4
    elif ip6:
        src, dst = ip6.src, ip6.dst
        ip_version = 6

    sport = dport = None
    if tcp:
        sport, dport = tcp.sport, tcp.dport
    elif udp:
        sport, dport = udp.sport, udp.dport

    payload_len = len(bytes(pkt)) - (len(bytes(eth)) if eth else 0)

    return {
        "ts": float(pkt.time),
        "iface": conf.iface if hasattr(conf, "iface") else None,
        "eth_src": eth.src if eth else None,
        "eth_dst": eth.dst if eth else None,
        "ip_version": ip_version,
        "src": src,
        "dst": dst,
        "proto": human_proto(pkt),
        "sport": sport,
        "dport": dport,
        "payload_len": payload_len,
    }

def fmt_row(d: Dict[str, Any]) -> str:
    ts_str = datetime.fromtimestamp(d["ts"]).strftime("%H:%M:%S")
    src = d["src"] or (d["eth_src"] or "?")
    dst = d["dst"] or (d["eth_dst"] or "?")
    proto = d["proto"]
    ports = ""
    if d["sport"] and d["dport"]:
        ports = f"{d['sport']}→{d['dport']}"
    return f"{ts_str}  {proto:<5}  {src:<18} -> {dst:<18} {ports:<11} len={d['payload_len']}"

def handle_packet(pkt):
    global pcap_writer, csv_writer, json_file_handle

    # print compact line
    data = extract(pkt)
    print(fmt_row(data))

    # write PCAP
    if pcap_writer:
        pcap_writer.write(pkt)

    # write CSV
    if csv_writer:
        csv_writer.writerow(data)

    # write JSONL
    if json_file_handle:
        json_file_handle.write(json.dumps(data) + "\n")

def setup_outputs(args):
    global pcap_writer, csv_writer, csv_file_handle, json_file_handle

    if args.pcap:
        pcap_writer = PcapWriter(args.pcap, append=True, sync=True)
    if args.csv:
        csv_file_handle = open(args.csv, "a", newline="")
        csv_writer = csv.DictWriter(csv_file_handle, fieldnames=[
            "ts","iface","eth_src","eth_dst","ip_version","src","dst","proto","sport","dport","payload_len"
        ])
        if args.csv_header and (os.stat(args.csv).st_size == 0):
            csv_writer.writeheader()
    if args.json:
        json_file_handle = open(args.json, "a")

def close_outputs():
    global pcap_writer, csv_writer, csv_file_handle, json_file_handle
    if pcap_writer:
        try: pcap_writer.close()
        except: pass
    if csv_file_handle:
        try: csv_file_handle.close()
        except: pass
    if json_file_handle:
        try: json_file_handle.close()
        except: pass

def on_sigint(sig, frame):
    global stop_requested
    print("\n[!] Ctrl+C received, stopping...", file=sys.stderr)
    stop_requested = True

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha — Basic Network Sniffer (Scapy)")
    parser.add_argument("-i","--iface", required=False, help="Interface to sniff on (e.g., eth0, wlan0). Default: Scapy's default.")
    parser.add_argument("-f","--filter", default=None, help="BPF filter (e.g., 'tcp', 'udp', 'icmp', 'port 53', 'tcp port 80').")
    parser.add_argument("-c","--count", type=int, default=0, help="Number of packets to capture (0 = unlimited).")
    parser.add_argument("-t","--timeout", type=int, default=None, help="Stop after N seconds.")
    parser.add_argument("--pcap", help="Write captured packets to this PCAP file.")
    parser.add_argument("--csv", help="Write parsed fields to this CSV file.")
    parser.add_argument("--csv-header", action="store_true", help="Write CSV header if file is empty.")
    parser.add_argument("--json", help="Write parsed fields to this JSONL file.")
    args = parser.parse_args()

    # Privilege hint
    if hasattr(os, "geteuid"):
        if os.geteuid() != 0:
            print("[!] Hint: capturing usually requires root. Try `sudo -E python3 sniffer.py ...`", file=sys.stderr)

    if args.iface:
        conf.iface = args.iface

    setup_outputs(args)

    # Handle Ctrl+C
    signal.signal(signal.SIGINT, on_sigint)

    print(f"[+] Starting capture (iface={getattr(conf,'iface',None)}, filter={args.filter!r}, count={args.count}, timeout={args.timeout})")
    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handle_packet,
            count=args.count if args.count > 0 else 0,
            timeout=args.timeout,
            store=False,
            stop_filter=lambda p: stop_requested
        )
    except PermissionError:
        print("[-] Permission denied. Run as root/admin.", file=sys.stderr)
    finally:
        close_outputs()
        print("[+] Done. Outputs (if any) are closed.")

if __name__ == "__main__":
    main()
