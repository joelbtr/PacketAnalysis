# Network Packet Analyzer

A Python packet analyzer built on Scapy. Live capture, PCAP analysis, protocol dissection across the full stack, and a stateful alert engine that detects port scans, ARP spoofing, SYN floods, and DNS exfiltration.

---

## Installation

```bash
git clone https://github.com/yourname/netanalyzer
cd netanalyzer
pip install -r requirements.txt
```

On Windows, Scapy requires [Npcap](https://npcap.com/#download) to be installed first. Download and install it before running anything.

---

## Usage

### Live capture

Requires Administrator (Windows) or root/sudo (Linux/macOS).

```bash
# Windows — run PowerShell as Administrator
python analyzer.py capture --iface "Wi-Fi" --count 200 --report report.html

# Linux / macOS
sudo python analyzer.py capture --iface eth0 --count 200 --report report.html
```

Find your interface name:
```bash
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

Flags:
```
--iface     Network interface to sniff on (required)
--count     Packets to capture before stopping (default: 0 = unlimited, Ctrl+C to stop)
--out       PCAP output file (default: capture.pcap)
--report    Generate HTML report after capture
--json      Save parsed packets as JSON
-v          Verbose mode — print every field of every packet
```

### Analyze a saved PCAP

No admin required. Works on any `.pcap` or `.pcapng` file — including ones from Wireshark, tcpdump, or a CTF.

```bash
python analyzer.py analyze capture.pcap --report report.html
python analyzer.py analyze challenge.pcapng --report report.html -v
```

---

## Live output

```
  IDX  TIMESTAMP            LAYERS                        SUMMARY
──────────────────────────────────────────────────────────────────────────────
    1  2025-01-10 14:22:01  Ethernet/IP/TCP               TCP 10.0.0.5:44000 → 192.168.1.1:80 [SYN]
    2  2025-01-10 14:22:01  Ethernet/IP/UDP/DNS            DNS query: example.com. from 10.0.0.5
    3  2025-01-10 14:22:01  Ethernet/ARP                  ARP request: who has 192.168.1.2? tell 192.168.1.1
   18  2025-01-10 14:22:01  Ethernet/IP/TCP               TCP 10.0.0.99:44000 → 192.168.1.10:15 [SYN]
  ⚠  [HIGH] Port Scan — 10.0.0.99: 15 distinct ports contacted in 10s
   23  2025-01-10 14:22:01  Ethernet/IP/UDP/DNS            DNS query: aaaa...evil.com from 192.168.1.55
  ⚠  [MEDIUM] DNS Exfiltration — 192.168.1.55: label 50 chars — possible exfil
```

---

## Protocol support

| Layer | Protocols |
|---|---|
| L2 | Ethernet (src/dst MAC, EtherType) |
| L3 | IPv4 (src/dst, TTL, protocol, flags), ARP (op, sender, target) |
| L4 | TCP (ports, flags, seq/ack, window), UDP (ports, length), ICMP (type, code) |
| L7 | HTTP (method, URI, Host header), DNS (queries, answers, RR types) |

---

## Alert engine

Four stateful detectors run on every packet. Each maintains its own state across the session.

### Port scan

Tracks distinct destination ports per source IP in a sliding 10-second window. Fires when ≥ 15 distinct ports are hit with SYN packets. Resets after firing so repeated scans are re-detected.

```
[HIGH] Port Scan — 10.0.0.99: 15 distinct ports contacted in 10s — likely port scan
```

### SYN flood

Counts raw SYN packets (without ACK) per source IP. Fires when ≥ 50 SYNs arrive within 5 seconds. Targets TCP stack exhaustion attacks.

```
[HIGH] SYN Flood — 10.0.0.5: 50 SYN packets in 5s — possible SYN flood / DoS
```

### ARP spoofing

Maintains an ARP table (`IP → MAC`). Fires when a known IP announces a different MAC address — the classic ARP poisoning / MITM signature. This is exactly how `arpwatch` works.

```
[HIGH] ARP Spoofing — 192.168.1.1: was aa:bb:cc:dd:ee:ff, now claims to be 11:22:33:44:55:66
```

### DNS exfiltration

Two independent heuristics:

1. **Long subdomain label** — a single DNS query with a label over 40 characters suggests base64 or hex-encoded data (e.g. `dGhpcyBpcyBleGZpbA==.evil.com`)
2. **High query rate** — ≥ 30 queries from one IP within 10 seconds suggests DNS tunneling

```
[MEDIUM] DNS Exfiltration — 192.168.1.55: label 50 chars in query for 'aaa...evil.com'
```

---

## HTML report

Generated with `--report report.html`. Self-contained, no external dependencies.

- Session stats (total packets, unique IPs, alert count, capture duration)
- Top talkers bar chart
- Alert cards with severity badges (HIGH / MEDIUM / LOW)
- Filterable packet table — click a protocol badge to filter to that protocol only

---

## Project structure

```
netanalyzer/
├── analyzer.py     # CLI entry point — capture and analyze subcommands
├── parser.py       # Layer-by-layer packet dissection (Ethernet → HTTP/DNS)
├── alerts.py       # Stateful alert engine — 4 detectors
├── sniffer.py      # Scapy sniff() and rdpcap() wrappers + live display
├── reporter.py     # HTML session report generator
├── requirements.txt
└── README.md
```

---

## Testing without live traffic

Build a synthetic PCAP with Scapy to test the alert engine without needing a live network:

```python
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

pkts = []

# Trigger port scan: 15 SYNs to different ports
for port in range(1, 16):
    pkts.append(Ether()/IP(src='10.0.0.99', dst='192.168.1.1')/TCP(dport=port, flags='S'))

# Trigger DNS exfil: long subdomain label
pkts.append(
    Ether()/IP(src='10.0.0.55', dst='8.8.8.8') /
    UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname='A'*50 + '.evil.com'))
)

wrpcap('test.pcap', pkts)
```

Then:
```bash
python analyzer.py analyze test.pcap --report report.html
```

---

## Notes

- **Live capture requires privileges** — on Windows, run PowerShell as Administrator; on Linux/macOS use `sudo`. The tool will print a clear error and exit if it lacks permission rather than silently capturing nothing.
- **HTTP detection is cleartext only** — the tool reads raw TCP payloads and checks for HTTP verbs. HTTPS traffic will show as plain TCP since it is encrypted.
- **Scapy on Windows requires Npcap** — WinPcap is not supported. Download Npcap from [npcap.com](https://npcap.com).

---

## License

MIT
