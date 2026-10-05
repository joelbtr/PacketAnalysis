"""
alerts.py — Stateful alert detection engine.

Each detector maintains state across packets (connection tracking,
per-IP counters, ARP table) and fires an alert when a threshold is crossed.

Detectors:
  - PortScanDetector:      >= N distinct ports from one src IP in T seconds
  - SynFloodDetector:      >= N SYN packets from one src IP in T seconds
  - ArpSpoofDetector:      same IP announced by > 1 MAC address
  - DnsExfilDetector:      unusually long or high-frequency DNS queries
"""

from collections import defaultdict
from datetime import datetime, timezone


# ------------------------------------------------------------------ #
#  Alert object                                                        #
# ------------------------------------------------------------------ #

class Alert:
    def __init__(self, kind: str, severity: str, src: str, detail: str):
        self.kind      = kind
        self.severity  = severity   # "HIGH" | "MEDIUM" | "LOW"
        self.src       = src
        self.detail    = detail
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "kind":      self.kind,
            "severity":  self.severity,
            "src":       self.src,
            "detail":    self.detail,
            "timestamp": self.timestamp,
        }

    def __str__(self):
        return f"[{self.severity}] {self.kind} — {self.src}: {self.detail}"


# ------------------------------------------------------------------ #
#  Port scan detector                                                  #
# ------------------------------------------------------------------ #

class PortScanDetector:
    """
    Tracks distinct destination ports contacted by each source IP
    within a sliding time window. Fires when >= threshold ports
    are seen.

    This catches horizontal scans (one IP -> many ports on one host)
    but also works for vertical scans (one IP -> same port on many hosts)
    with a small modification — here we focus on the classic case.
    """

    def __init__(self, threshold: int = 15, window_seconds: float = 10.0):
        self.threshold = threshold
        self.window    = window_seconds
        # src_ip -> list of (timestamp, dst_port)
        self._state: dict = defaultdict(list)

    def process(self, parsed: dict) -> Alert | None:
        tcp = parsed.get("tcp")
        if not tcp:
            return None
        ip = parsed.get("ip", {})
        src = ip.get("src")
        dst_port = tcp.get("dport")
        if not src or not dst_port:
            return None

        # Only count SYN packets (connection initiation)
        if "SYN" not in tcp.get("flags", []):
            return None

        now = _ts_to_float(parsed["timestamp"])
        entries = self._state[src]
        # Evict entries outside the window
        entries = [(t, p) for t, p in entries if now - t <= self.window]
        entries.append((now, dst_port))
        self._state[src] = entries

        distinct_ports = len(set(p for _, p in entries))
        if distinct_ports >= self.threshold:
            self._state[src] = []  # reset after firing
            return Alert(
                kind="Port Scan",
                severity="HIGH",
                src=src,
                detail=(
                    f"{distinct_ports} distinct ports contacted in "
                    f"{self.window:.0f}s — likely port scan"
                ),
            )
        return None


# ------------------------------------------------------------------ #
#  SYN flood detector                                                  #
# ------------------------------------------------------------------ #

class SynFloodDetector:
    """
    Counts SYN packets per source IP per window. A high rate of
    SYNs without corresponding SYN-ACKs completing is a SYN flood.
    We approximate by raw SYN rate since we don't track full state here.
    """

    def __init__(self, threshold: int = 50, window_seconds: float = 5.0):
        self.threshold = threshold
        self.window    = window_seconds
        self._state: dict = defaultdict(list)

    def process(self, parsed: dict) -> Alert | None:
        tcp = parsed.get("tcp")
        if not tcp or "SYN" not in tcp.get("flags", []) or "ACK" in tcp.get("flags", []):
            return None
        src = parsed.get("ip", {}).get("src")
        if not src:
            return None

        now = _ts_to_float(parsed["timestamp"])
        entries = self._state[src]
        entries = [t for t in entries if now - t <= self.window]
        entries.append(now)
        self._state[src] = entries

        if len(entries) >= self.threshold:
            self._state[src] = []
            return Alert(
                kind="SYN Flood",
                severity="HIGH",
                src=src,
                detail=(
                    f"{len(entries)} SYN packets in {self.window:.0f}s "
                    f"— possible SYN flood / DoS"
                ),
            )
        return None


# ------------------------------------------------------------------ #
#  ARP spoofing detector                                               #
# ------------------------------------------------------------------ #

class ArpSpoofDetector:
    """
    Maintains an ARP table (IP -> MAC). Fires when an IP that was
    previously associated with one MAC is announced by a different MAC.

    This is exactly how arpwatch works.
    """

    def __init__(self):
        # ip -> mac (first seen)
        self._table: dict = {}

    def process(self, parsed: dict) -> Alert | None:
        arp = parsed.get("arp")
        if not arp:
            return None

        sender_ip  = arp.get("sender_ip")
        sender_mac = arp.get("sender_mac")
        if not sender_ip or not sender_mac:
            return None

        # Ignore broadcast MACs
        if sender_mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None

        known_mac = self._table.get(sender_ip)
        if known_mac is None:
            self._table[sender_ip] = sender_mac
            return None

        if known_mac != sender_mac:
            return Alert(
                kind="ARP Spoofing",
                severity="HIGH",
                src=sender_ip,
                detail=(
                    f"IP {sender_ip} was {known_mac}, now claims to be "
                    f"{sender_mac} — possible ARP poisoning / MITM"
                ),
            )
        return None


# ------------------------------------------------------------------ #
#  DNS exfiltration detector                                           #
# ------------------------------------------------------------------ #

class DnsExfilDetector:
    """
    Two heuristics:
      1. Unusually long subdomain label (> 40 chars) — base64/hex encoded data
      2. High query rate from one source (> threshold in window)

    DNS exfiltration encodes data in subdomain labels and sends them
    to an attacker-controlled nameserver. The labels are often very long
    and/or high-frequency.
    """

    def __init__(self, label_len: int = 40, rate_threshold: int = 30, window_seconds: float = 10.0):
        self.label_len      = label_len
        self.rate_threshold = rate_threshold
        self.window         = window_seconds
        self._state: dict   = defaultdict(list)

    def process(self, parsed: dict) -> Alert | None:
        dns = parsed.get("dns")
        if not dns or dns.get("qr") != "query":
            return None

        src = parsed.get("ip", {}).get("src", "?")
        questions = dns.get("questions", [])

        for q in questions:
            name = q.get("name", "")
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            name = name.rstrip(".")

            # Heuristic 1: long subdomain label
            labels = name.split(".")
            longest = max((len(l) for l in labels), default=0)
            if longest > self.label_len:
                return Alert(
                    kind="DNS Exfiltration",
                    severity="MEDIUM",
                    src=src,
                    detail=(
                        f"Suspiciously long DNS label ({longest} chars) in "
                        f"query for '{name}' — possible data exfiltration"
                    ),
                )

        # Heuristic 2: high query rate
        now = _ts_to_float(parsed["timestamp"])
        entries = self._state[src]
        entries = [t for t in entries if now - t <= self.window]
        entries.append(now)
        self._state[src] = entries

        if len(entries) >= self.rate_threshold:
            self._state[src] = []
            return Alert(
                kind="DNS Exfiltration",
                severity="MEDIUM",
                src=src,
                detail=(
                    f"{len(entries)} DNS queries in {self.window:.0f}s "
                    f"from {src} — possible tunneling / exfiltration"
                ),
            )
        return None


# ------------------------------------------------------------------ #
#  Engine — runs all detectors on each packet                         #
# ------------------------------------------------------------------ #

class AlertEngine:
    def __init__(self):
        self.detectors = [
            PortScanDetector(),
            SynFloodDetector(),
            ArpSpoofDetector(),
            DnsExfilDetector(),
        ]
        self.alerts: list = []

    def process(self, parsed: dict) -> list:
        """Run all detectors. Returns list of any new Alert objects."""
        new_alerts = []
        for detector in self.detectors:
            try:
                alert = detector.process(parsed)
                if alert:
                    self.alerts.append(alert)
                    new_alerts.append(alert)
                    print(f"  ⚠  {alert}")
            except Exception:
                pass
        return new_alerts


# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

def _ts_to_float(ts_str: str) -> float:
    """Convert ISO 8601 timestamp to Unix float for arithmetic."""
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except Exception:
        return 0.0
