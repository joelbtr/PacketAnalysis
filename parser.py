"""
parser.py — Layer-by-layer packet dissection.

Takes a Scapy packet and returns a normalised dict with all
relevant fields extracted at each protocol layer.

Layer stack handled:
  L2: Ethernet (src/dst MAC)
  L3: IP (src/dst IP, TTL, protocol)
  L4: TCP (ports, flags, seq/ack), UDP (ports, length), ICMP (type/code)
  L7: HTTP (method, host, uri), DNS (query/response), ARP (op, sender, target)
"""

from datetime import datetime, timezone


# TCP flag bitmask -> human-readable names
TCP_FLAGS = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}

# ICMP type codes
ICMP_TYPES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    5:  "Redirect",
    8:  "Echo Request",
    11: "Time Exceeded",
}


def _parse_tcp_flags(flags_int: int) -> list:
    return [name for bit, name in TCP_FLAGS.items() if flags_int & bit]


def _try_decode(b) -> str:
    """Safely decode bytes to string, falling back to hex."""
    if isinstance(b, bytes):
        try:
            return b.decode("utf-8", errors="replace")
        except Exception:
            return b.hex()
    return str(b)


def parse_packet(pkt) -> dict:
    """
    Dissect a single Scapy packet into a normalised dict.
    Works on both live-captured and PCAP-read packets.
    """
    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "layers": [],
        "summary": "",
    }

    # Try to get the real packet timestamp if available (PCAP packets have it)
    if hasattr(pkt, "time"):
        try:
            result["timestamp"] = datetime.fromtimestamp(
                float(pkt.time), tz=timezone.utc
            ).isoformat()
        except Exception:
            pass

    # ---------------------------------------------------------------- #
    #  L2 — Ethernet                                                    #
    # ---------------------------------------------------------------- #
    if pkt.haslayer("Ether"):
        eth = pkt["Ether"]
        result["eth"] = {
            "src": eth.src,
            "dst": eth.dst,
            "type": hex(eth.type),
        }
        result["layers"].append("Ethernet")

    # ---------------------------------------------------------------- #
    #  L3 — IP                                                          #
    # ---------------------------------------------------------------- #
    if pkt.haslayer("IP"):
        ip = pkt["IP"]
        result["ip"] = {
            "src": ip.src,
            "dst": ip.dst,
            "ttl": ip.ttl,
            "proto": ip.proto,
            "len": ip.len,
            "flags": str(ip.flags),
        }
        result["layers"].append("IP")

    # ---------------------------------------------------------------- #
    #  L3 — ARP (sits directly on Ethernet, no IP layer)               #
    # ---------------------------------------------------------------- #
    elif pkt.haslayer("ARP"):
        arp = pkt["ARP"]
        op_name = "request" if arp.op == 1 else "reply"
        result["arp"] = {
            "op": op_name,
            "sender_mac": arp.hwsrc,
            "sender_ip":  arp.psrc,
            "target_mac": arp.hwdst,
            "target_ip":  arp.pdst,
        }
        result["layers"].append("ARP")
        result["summary"] = f"ARP {op_name}: who has {arp.pdst}? tell {arp.psrc}"
        return result

    # ---------------------------------------------------------------- #
    #  L4 — TCP                                                         #
    # ---------------------------------------------------------------- #
    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        flags = _parse_tcp_flags(int(tcp.flags))
        result["tcp"] = {
            "sport": tcp.sport,
            "dport": tcp.dport,
            "flags": flags,
            "seq":   tcp.seq,
            "ack":   tcp.ack,
            "window": tcp.window,
        }
        result["layers"].append("TCP")

        # L7 — HTTP (crude but effective for cleartext traffic)
        if pkt.haslayer("Raw"):
            raw = _try_decode(pkt["Raw"].load)
            if raw.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                lines = raw.split("\r\n")
                method_line = lines[0].split(" ")
                result["http"] = {
                    "method": method_line[0] if len(method_line) > 0 else "",
                    "uri":    method_line[1] if len(method_line) > 1 else "",
                    "host":   next((l.split(": ", 1)[1] for l in lines if l.lower().startswith("host:")), ""),
                    "raw":    raw[:512],
                }
                result["layers"].append("HTTP")
                src_ip = result.get("ip", {}).get("src", "?")
                result["summary"] = (
                    f"HTTP {result['http']['method']} {result['http']['host']}"
                    f"{result['http']['uri']} from {src_ip}"
                )
            elif "HTTP/" in raw:
                status_line = raw.split("\r\n")[0]
                result["http"] = {
                    "type":   "response",
                    "status": status_line,
                    "raw":    raw[:512],
                }
                result["layers"].append("HTTP")

    # ---------------------------------------------------------------- #
    #  L4 — UDP                                                         #
    # ---------------------------------------------------------------- #
    elif pkt.haslayer("UDP"):
        udp = pkt["UDP"]
        result["udp"] = {
            "sport": udp.sport,
            "dport": udp.dport,
            "len":   udp.len,
        }
        result["layers"].append("UDP")

        # L7 — DNS
        if pkt.haslayer("DNS"):
            dns = pkt["DNS"]
            result["dns"] = {
                "id":   dns.id,
                "qr":   "response" if dns.qr else "query",
                "opcode": dns.opcode,
                "questions": [],
                "answers":   [],
            }
            # Questions
            if dns.qd:
                qd = dns.qd
                while qd:
                    try:
                        result["dns"]["questions"].append({
                            "name":  _try_decode(qd.qname),
                            "type":  qd.qtype,
                        })
                    except Exception:
                        pass
                    qd = qd.payload if hasattr(qd, "payload") else None
                    if not hasattr(qd, "qname"):
                        break

            # Answers
            if dns.an:
                an = dns.an
                while an:
                    try:
                        ans = {"name": _try_decode(an.rrname), "type": an.type}
                        if hasattr(an, "rdata"):
                            ans["rdata"] = str(an.rdata)
                        result["dns"]["answers"].append(ans)
                    except Exception:
                        pass
                    an = an.payload if hasattr(an, "payload") else None
                    if not hasattr(an, "rrname"):
                        break

            result["layers"].append("DNS")
            q = result["dns"]["questions"]
            src = result.get("ip", {}).get("src", "?")
            if q:
                result["summary"] = f"DNS {result['dns']['qr']}: {q[0]['name']} from {src}"

    # ---------------------------------------------------------------- #
    #  L4 — ICMP                                                        #
    # ---------------------------------------------------------------- #
    elif pkt.haslayer("ICMP"):
        icmp = pkt["ICMP"]
        result["icmp"] = {
            "type": icmp.type,
            "type_name": ICMP_TYPES.get(icmp.type, f"type {icmp.type}"),
            "code": icmp.code,
            "id":   getattr(icmp, "id", None),
            "seq":  getattr(icmp, "seq", None),
        }
        result["layers"].append("ICMP")
        src = result.get("ip", {}).get("src", "?")
        dst = result.get("ip", {}).get("dst", "?")
        result["summary"] = f"ICMP {result['icmp']['type_name']}: {src} → {dst}"

    # ---------------------------------------------------------------- #
    #  Default summary (if nothing more specific set above)             #
    # ---------------------------------------------------------------- #
    if not result["summary"]:
        src = result.get("ip", {}).get("src", "?")
        dst = result.get("ip", {}).get("dst", "?")
        tcp = result.get("tcp")
        udp = result.get("udp")
        if tcp:
            flags_str = "+".join(tcp["flags"]) if tcp["flags"] else "—"
            result["summary"] = (
                f"TCP {src}:{tcp['sport']} → {dst}:{tcp['dport']} [{flags_str}]"
            )
        elif udp:
            result["summary"] = (
                f"UDP {src}:{udp['sport']} → {dst}:{udp['dport']}"
            )
        elif "ip" in result:
            result["summary"] = f"IP {src} → {dst}"
        else:
            result["summary"] = "/".join(result["layers"]) or "Unknown"

    return result
