"""
sniffer.py — Live packet capture and PCAP reading via Scapy.

Live capture:
  - Sniffs on a given interface using scapy.sniff()
  - Calls parser.parse_packet() on each packet
  - Feeds parsed result to AlertEngine
  - Prints a live one-line summary per packet
  - Optionally writes raw packets to a PCAP file

PCAP analysis:
  - Reads a saved PCAP with scapy.rdpcap()
  - Same parse + alert pipeline
"""

import sys
from parser import parse_packet
from alerts import AlertEngine

# Terminal color codes (stripped on Windows if not supported)
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
RESET  = "\033[0m"

PROTO_COLORS = {
    "HTTP":     GREEN,
    "DNS":      CYAN,
    "TCP":      "",
    "UDP":      "",
    "ICMP":     YELLOW,
    "ARP":      YELLOW,
    "Ethernet": GRAY,
}


def _color_for(parsed: dict) -> str:
    for proto in ("HTTP", "DNS", "ICMP", "ARP"):
        if proto in parsed.get("layers", []):
            return PROTO_COLORS[proto]
    return ""


def _print_packet(parsed: dict, idx: int):
    color = _color_for(parsed)
    layers = "/".join(parsed.get("layers", ["?"]))
    ts = parsed.get("timestamp", "")[:19].replace("T", " ")
    summary = parsed.get("summary", "")
    print(f"{GRAY}{idx:>5}  {ts}  {RESET}{color}{layers:<28}{RESET}  {summary}")


def live_capture(
    iface: str,
    count: int = 0,
    pcap_out: str = None,
    alert_engine: AlertEngine = None,
    verbose: bool = False,
) -> list:
    """
    Capture packets live from `iface`.

    Args:
        iface:        Network interface name (e.g. "eth0", "Wi-Fi")
        count:        Number of packets to capture (0 = until Ctrl+C)
        pcap_out:     Optional path to write a PCAP file
        alert_engine: AlertEngine instance; created internally if None
        verbose:      Print every packet field, not just summary

    Returns:
        List of parsed packet dicts.
    """
    try:
        from scapy.all import sniff, wrpcap
    except ImportError:
        print("[!] Scapy not installed — run: pip install scapy")
        sys.exit(1)

    if alert_engine is None:
        alert_engine = AlertEngine()

    parsed_packets = []
    raw_packets    = []

    print(f"[*] Capturing on {iface}  (count={'∞' if count == 0 else count})  Ctrl+C to stop\n")
    print(f"{'  IDX':>6}  {'TIMESTAMP':19}  {'LAYERS':<28}  SUMMARY")
    print("─" * 90)

    def _handle(pkt):
        parsed = parse_packet(pkt)
        parsed_packets.append(parsed)
        raw_packets.append(pkt)
        _print_packet(parsed, len(parsed_packets))

        if verbose:
            import json
            print(json.dumps(parsed, indent=2, default=str))

        alert_engine.process(parsed)

    try:
        sniff(iface=iface, prn=_handle, count=count, store=False)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped.")
    except PermissionError:
        print("[!] Permission denied — run as Administrator (Windows) or with sudo (Linux/macOS)")
        sys.exit(1)

    if pcap_out and raw_packets:
        wrpcap(pcap_out, raw_packets)
        print(f"[+] PCAP written to {pcap_out}")

    print(f"\n[+] {len(parsed_packets)} packets captured. {len(alert_engine.alerts)} alert(s) fired.")
    return parsed_packets


def analyze_pcap(
    pcap_path: str,
    alert_engine: AlertEngine = None,
    verbose: bool = False,
) -> list:
    """
    Read and analyze a saved PCAP file.

    Args:
        pcap_path:    Path to .pcap or .pcapng file
        alert_engine: AlertEngine instance
        verbose:      Print full parsed dict per packet

    Returns:
        List of parsed packet dicts.
    """
    try:
        from scapy.all import rdpcap
    except ImportError:
        print("[!] Scapy not installed — run: pip install scapy")
        sys.exit(1)

    if alert_engine is None:
        alert_engine = AlertEngine()

    print(f"[*] Reading PCAP: {pcap_path}")
    packets = rdpcap(pcap_path)
    print(f"[*] {len(packets)} packets loaded\n")

    print(f"{'  IDX':>6}  {'TIMESTAMP':19}  {'LAYERS':<28}  SUMMARY")
    print("─" * 90)

    parsed_packets = []
    for pkt in packets:
        parsed = parse_packet(pkt)
        parsed_packets.append(parsed)
        _print_packet(parsed, len(parsed_packets))

        if verbose:
            import json
            print(json.dumps(parsed, indent=2, default=str))

        alert_engine.process(parsed)

    print(f"\n[+] {len(parsed_packets)} packets analyzed. {len(alert_engine.alerts)} alert(s) fired.")
    return parsed_packets
