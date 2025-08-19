# CodeAlpha — Basic Network Sniffer (Python)

A simple, educational network packet sniffer built with **Scapy** that captures packets, parses key fields (src/dst IP, protocol, ports, lengths), prints a live stream to the console, and optionally saves to **PCAP**, **CSV**, and **JSONL** for later analysis.

> ⚠️ Use only on networks you own or where you have explicit permission. Capturing traffic may be illegal otherwise.

---

## ✨ Features
- Live capture on a chosen interface (e.g., `eth0`, `wlan0`, `Ethernet`).
- BPF capture filter support (e.g., `tcp port 80`, `udp`, `icmp`).
- Pretty, compact console output.
- Optional output formats: **PCAP**, **CSV**, **JSONL**.
- Extracts: timestamps, MACs, IPs, L4 protocol (TCP/UDP/ICMP), ports, payload length.
- Works on Linux/macOS (root required). Windows supported with Npcap + admin.

---

## 📦 Project Structure
```
CodeAlpha_BasicNetworkSniffer/
├─ sniffer.py            # Scapy-based sniffer (recommended)
├─ socket_sniffer.py     # Minimal raw-socket example (Linux only)
├─ requirements.txt
├─ README.md
└─ .gitignore
```

---

## 🚀 Quickstart (Kali/Linux)

1) **Create & activate venv (optional but recommended)**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2) **Install dependencies**
```bash
pip install -r requirements.txt
```

3) **Run with sudo (packet capture needs elevated privileges)**
```bash
sudo -E python3 sniffer.py --iface eth0 --filter "tcp" --count 50 --pcap out.pcap --csv out.csv --json out.jsonl
```
- Replace `eth0` with your interface (e.g., `wlan0`). On Windows, run an elevated terminal and set `--iface` to your adapter's name.

4) **Stop** anytime with `Ctrl+C` (it will finalize outputs).

---

## 🧪 More Examples

Capture 100 ICMP packets (pings) and just print to console:
```bash
sudo -E python3 sniffer.py -i eth0 -f "icmp" -c 100
```

Capture TCP port 80 packets for 30 seconds, save to PCAP & JSONL:
```bash
sudo -E python3 sniffer.py -i eth0 -f "tcp port 80" -t 30 --pcap web.pcap --json web.jsonl
```

Linux-only raw socket demo (no Scapy, IPv4 only, requires root):
```bash
sudo -E python3 socket_sniffer.py -i eth0
```

---

## 🧰 Fields Collected
- `ts` (float seconds), `iface`, `eth_src`, `eth_dst`
- `ip_version`, `src`, `dst`, `proto` (TCP/UDP/ICMP/Other)
- `sport`, `dport` (if TCP/UDP), `payload_len`

---

## 🧾 Outputs
- **PCAP** — open with Wireshark: `File → Open → out.pcap`
- **CSV** — spreadsheet-friendly
- **JSONL** — one JSON per line, great for scripting

---

## 🔒 Legal & Ethical
Use on **your own lab** or **authorized environments** only. Be mindful of local laws and organizational policies. This is an educational tool.

---

## 🧑‍💻 For CodeAlpha Submission

**Repo name:** `CodeAlpha_BasicNetworkSniffer`

**Suggested commit steps:**
```bash
git init
git add .
git commit -m "Initial commit: basic sniffer with PCAP/CSV/JSON outputs"
git branch -M main
git remote add origin https://github.com/<your-username>/CodeAlpha_BasicNetworkSniffer.git
git push -u origin main
```

**LinkedIn post checklist:**
- ✅ Short explainer (what you built & why)
- ✅ 30–60 sec demo clip or screen recording
- ✅ GitHub link
- ✅ Tag **@CodeAlpha** and add relevant hashtags (#CyberSecurity #Python #Scapy)

**Submission checklist:**
- ✅ Completed code in public GitHub repo
- ✅ Short demo video posted on LinkedIn (with repo link)
- ✅ Submission form filled

---

## 📝 Sample LinkedIn Caption

> Built a **Basic Network Sniffer** in Python for my @CodeAlpha internship. It captures live traffic, shows IPs, protocols, ports, and saves to PCAP/CSV/JSON for analysis. Learned a lot about packet structure and BPF filters!  
> GitHub: <your repo link>  
> #CyberSecurity #Python #Scapy #Networking #Internship #CodeAlpha

---

## 🆘 Troubleshooting
- **PermissionError / no packets** → Run as root/admin. On Linux, use `sudo -E`.
- **No interface found** → List interfaces with `ip link` (Linux) or `scapy.get_if_list()`.
- **Windows** → Install **Npcap**, run terminal as Administrator.
- **Filter errors** → Keep BPF simple (e.g., `tcp`, `udp`, `icmp`, `port 53`).

---

## 📚 Learn More
- Scapy docs: `from scapy.all import *` is powerful! Try `pkt.show()` inside callback to see full structure.
- Compare with Wireshark to deepen protocol understanding.

---

Happy hacking (ethically)!
