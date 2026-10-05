#!/usr/bin/env python3
"""
analyzer.py — Network Packet Analyzer
Subcommands: capture, analyze

Usage:
  # Live capture (requires admin/root)
  python analyzer.py capture --iface eth0 --count 100 --out capture.pcap

  # Analyze a saved PCAP
  python analyzer.py analyze capture.pcap --report report.html
"""

import argparse
import json
import sys

BANNER = """
╔══════════════════════════════════════════════════════╗
║         Network Packet Analyzer — Scapy              ║
╚══════════════════════════════════════════════════════╝
"""


def cmd_capture(args):
    from alerts import AlertEngine
    from sniffer import live_capture
    from reporter import generate_report

    engine = AlertEngine()
    parsed = live_capture(
        iface=args.iface,
        count=args.count,
        pcap_out=args.out,
        alert_engine=engine,
        verbose=args.verbose,
    )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(parsed, f, indent=2, default=str)
        print(f"[+] Parsed packets saved to {args.json}")

    if args.report:
        generate_report(parsed, engine.alerts, args.report, title=f"Capture on {args.iface}")


def cmd_analyze(args):
    from alerts import AlertEngine
    from sniffer import analyze_pcap
    from reporter import generate_report

    engine = AlertEngine()
    parsed = analyze_pcap(
        pcap_path=args.pcap,
        alert_engine=engine,
        verbose=args.verbose,
    )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(parsed, f, indent=2, default=str)
        print(f"[+] Parsed packets saved to {args.json}")

    report_out = args.report or "report.html"
    generate_report(parsed, engine.alerts, report_out, title=f"Analysis: {args.pcap}")
    print(f"[+] Open {report_out} in your browser.")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Network Packet Analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    # capture
    p_cap = sub.add_parser("capture", help="Live packet capture")
    p_cap.add_argument("--iface", required=True, help="Network interface (e.g. eth0, Wi-Fi)")
    p_cap.add_argument("--count", type=int, default=0, help="Packets to capture (0=unlimited)")
    p_cap.add_argument("--out",   default="capture.pcap", help="PCAP output file")
    p_cap.add_argument("--report", help="Generate HTML report after capture")
    p_cap.add_argument("--json",   help="Save parsed packets as JSON")
    p_cap.add_argument("-v", "--verbose", action="store_true")

    # analyze
    p_ana = sub.add_parser("analyze", help="Analyze a saved PCAP file")
    p_ana.add_argument("pcap", help="Path to .pcap file")
    p_ana.add_argument("--report", help="Output HTML report path (default: report.html)")
    p_ana.add_argument("--json",   help="Save parsed packets as JSON")
    p_ana.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    dispatch = {"capture": cmd_capture, "analyze": cmd_analyze}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
