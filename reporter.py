"""
reporter.py — HTML session report generator.

Ingests parsed packet list + alert list and produces
a self-contained HTML report with:
  - Session stats (total packets, protocols seen, top talkers)
  - Alert summary with severity badges
  - Full packet table (filterable by protocol)
"""

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_STYLE = {
    "HIGH":   ("background:#FAECE7;color:#993C1D", "⚠"),
    "MEDIUM": ("background:#FAEEDA;color:#854F0B", "△"),
    "LOW":    ("background:#EAF3DE;color:#3B6D11", "ℹ"),
}

REPORT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f5f5f5; color: #1a1a1a; padding: 32px 20px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 22px; font-weight: 500; margin-bottom: 4px; }}
  .sub {{ font-size: 13px; color: #888; margin-bottom: 28px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px,1fr));
    gap: 12px; margin-bottom: 28px; }}
  .stat {{ background:#fff; border-radius:10px; padding:16px;
    border:0.5px solid #e0e0e0; }}
  .stat-label {{ font-size:11px; color:#999; text-transform:uppercase;
    letter-spacing:.06em; margin-bottom:4px; }}
  .stat-value {{ font-size:24px; font-weight:500; }}
  .section {{ font-size:12px; font-weight:500; text-transform:uppercase;
    letter-spacing:.06em; color:#aaa; margin:24px 0 10px; }}
  .alerts {{ display:flex; flex-direction:column; gap:8px; margin-bottom:28px; }}
  .alert-card {{ background:#fff; border-radius:8px; padding:12px 16px;
    border:0.5px solid #e0e0e0; display:flex; align-items:flex-start; gap:12px; }}
  .badge {{ font-size:11px; font-weight:600; padding:3px 10px;
    border-radius:20px; white-space:nowrap; }}
  .alert-detail {{ font-size:13px; }}
  .alert-ts {{ font-size:11px; color:#bbb; font-family:monospace; margin-top:3px; }}
  .filter-row {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:10px; }}
  .fbtn {{ font-size:12px; padding:4px 12px; border-radius:20px;
    background:transparent; border:0.5px solid #d0d0d0; cursor:pointer; color:#555; }}
  .fbtn.active {{ background:#1a1a1a; color:#fff; border-color:#1a1a1a; }}
  table {{ width:100%; border-collapse:collapse; background:#fff;
    border-radius:10px; overflow:hidden; border:0.5px solid #e0e0e0; font-size:12px; }}
  th {{ background:#f9f9f9; text-align:left; padding:8px 12px;
    border-bottom:1px solid #eee; font-weight:500; color:#555; font-size:11px;
    text-transform:uppercase; letter-spacing:.04em; }}
  td {{ padding:7px 12px; border-bottom:0.5px solid #f0f0f0;
    font-family:monospace; vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  tr.hidden {{ display:none; }}
  .proto-badge {{ display:inline-block; font-size:10px; padding:2px 7px;
    border-radius:10px; font-weight:500; }}
  .proto-HTTP    {{ background:#EAF3DE; color:#3B6D11; }}
  .proto-DNS     {{ background:#E6F1FB; color:#185FA5; }}
  .proto-TCP     {{ background:#EEEDFE; color:#534AB7; }}
  .proto-UDP     {{ background:#F1EFE8; color:#5F5E5A; }}
  .proto-ICMP    {{ background:#FAEEDA; color:#854F0B; }}
  .proto-ARP     {{ background:#FAECE7; color:#993C1D; }}
  .proto-default {{ background:#F1EFE8; color:#5F5E5A; }}
  .talkers {{ background:#fff; border-radius:10px; padding:16px 20px;
    border:0.5px solid #e0e0e0; margin-bottom:28px; }}
  .bar-row {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
  .bar-ip {{ font-size:12px; font-family:monospace; width:140px; flex-shrink:0; }}
  .bar-track {{ flex:1; background:#f0f0f0; border-radius:4px; height:12px; }}
  .bar-fill {{ height:100%; border-radius:4px; background:#534AB7; }}
  .bar-n {{ font-size:11px; color:#aaa; width:32px; text-align:right; }}
</style>
</head>
<body>
<div class="container">
  <h1>Packet capture report</h1>
  <p class="sub">{title} — {generated_at}</p>

  <div class="stats">
    <div class="stat"><div class="stat-label">Total packets</div>
      <div class="stat-value">{total}</div></div>
    <div class="stat"><div class="stat-label">Alerts fired</div>
      <div class="stat-value" style="color:#c53030">{alert_count}</div></div>
    <div class="stat"><div class="stat-label">Unique IPs</div>
      <div class="stat-value">{unique_ips}</div></div>
    <div class="stat"><div class="stat-label">Protocols</div>
      <div class="stat-value">{proto_count}</div></div>
    <div class="stat"><div class="stat-label">Duration</div>
      <div class="stat-value" style="font-size:16px">{duration}</div></div>
  </div>

  <p class="section">Top talkers</p>
  <div class="talkers">{talker_bars}</div>

  <p class="section">Alerts ({alert_count})</p>
  <div class="alerts">{alerts_html}</div>

  <p class="section">Packet log</p>
  <div class="filter-row" id="filters">
    <button class="fbtn active" onclick="filter('all',this)">All</button>
    {filter_buttons}
  </div>
  <table id="pkt-table">
    <thead><tr>
      <th>#</th><th>Timestamp</th><th>Protocol</th><th>Summary</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<script>
function filter(proto, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#pkt-table tbody tr').forEach(tr => {{
    tr.classList.toggle('hidden', proto !== 'all' && tr.dataset.proto !== proto);
  }});
}}
</script>
</body>
</html>
"""


def _proto_badge(layers: list) -> tuple:
    """Return (top_proto, badge_html)."""
    priority = ["HTTP", "DNS", "ICMP", "ARP", "TCP", "UDP"]
    top = next((p for p in priority if p in layers), layers[0] if layers else "?")
    cls = f"proto-{top}" if top in ("HTTP","DNS","TCP","UDP","ICMP","ARP") else "proto-default"
    return top, f'<span class="proto-badge {cls}">{top}</span>'


def _talker_bars(ip_counter: Counter, total: int) -> str:
    if not ip_counter:
        return "<p style='color:#bbb;font-size:13px'>No IP traffic.</p>"
    bars = []
    for ip, count in ip_counter.most_common(10):
        pct = int((count / total) * 100) if total else 0
        bars.append(f"""
        <div class="bar-row">
          <span class="bar-ip">{ip}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct}%"></div></div>
          <span class="bar-n">{count}</span>
        </div>""")
    return "".join(bars)


def generate_report(
    parsed_packets: list,
    alerts: list,
    output_path: str,
    title: str = "Capture Session",
) -> str:
    total = len(parsed_packets)

    # Protocol counter
    proto_counter: Counter = Counter()
    ip_counter: Counter    = Counter()
    timestamps = []

    for p in parsed_packets:
        layers = p.get("layers", [])
        top, _ = _proto_badge(layers)
        proto_counter[top] += 1
        src = p.get("ip", {}).get("src")
        if src:
            ip_counter[src] += 1
        ts = p.get("timestamp", "")
        if ts:
            timestamps.append(ts)

    # Duration
    if len(timestamps) >= 2:
        from datetime import datetime
        try:
            t0 = datetime.fromisoformat(min(timestamps))
            t1 = datetime.fromisoformat(max(timestamps))
            secs = (t1 - t0).total_seconds()
            duration = f"{secs:.1f}s"
        except Exception:
            duration = "—"
    else:
        duration = "—"

    # Alerts HTML
    alerts_html = ""
    for a in alerts:
        d = a.to_dict() if hasattr(a, "to_dict") else a
        sev = d.get("severity", "LOW")
        style, icon = SEVERITY_STYLE.get(sev, SEVERITY_STYLE["LOW"])
        alerts_html += f"""
        <div class="alert-card">
          <span class="badge" style="{style}">{icon} {sev}</span>
          <div>
            <div class="alert-detail"><strong>{d.get('kind','?')}</strong>
              — {d.get('src','?')}: {d.get('detail','')}</div>
            <div class="alert-ts">{d.get('timestamp','')[:19].replace('T',' ')}</div>
          </div>
        </div>"""
    if not alerts_html:
        alerts_html = "<p style='color:#bbb;font-size:13px;padding:8px 0'>No alerts fired.</p>"

    # Filter buttons
    protos = sorted(proto_counter.keys())
    filter_buttons = "".join(
        f'<button class="fbtn" onclick="filter(\'{p}\',this)">{p} ({proto_counter[p]})</button>'
        for p in protos
    )

    # Packet rows
    rows = ""
    for i, p in enumerate(parsed_packets, 1):
        layers = p.get("layers", [])
        top, badge = _proto_badge(layers)
        ts = p.get("timestamp", "")[:19].replace("T", " ")
        summary = p.get("summary", "")
        rows += f'<tr data-proto="{top}"><td>{i}</td><td>{ts}</td><td>{badge}</td><td>{summary}</td></tr>\n'

    html = REPORT_HTML.format(
        title=title,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total=total,
        alert_count=len(alerts),
        unique_ips=len(ip_counter),
        proto_count=len(proto_counter),
        duration=duration,
        talker_bars=_talker_bars(ip_counter, total),
        alerts_html=alerts_html,
        filter_buttons=filter_buttons,
        rows=rows,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] Report written to {output_path}")
    return output_path
